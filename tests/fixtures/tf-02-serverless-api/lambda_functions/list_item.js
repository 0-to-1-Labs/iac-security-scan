const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, QueryCommand } = require('@aws-sdk/lib-dynamodb');

const client = new DynamoDBClient({ region: process.env.REGION });
const docClient = DynamoDBDocumentClient.from(client);

exports.handler = async (event) => {
  console.log('Event:', JSON.stringify(event, null, 2));

  try {
    // Extract user ID from Cognito authorizer context
    const userId = event.requestContext?.authorizer?.claims?.sub;

    if (!userId) {
      return {
        statusCode: 401,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({ message: 'Unauthorized' })
      };
    }

    // Parse query parameters
    const queryParams = event.queryStringParameters || {};
    const limit = parseInt(queryParams.limit) || 20;
    const status = queryParams.status;
    const category = queryParams.category;

    let queryInput = {
      TableName: process.env.TABLE_NAME,
      Limit: limit
    };

    // Query by user_id using UserIndex
    if (!status && !category) {
      queryInput = {
        ...queryInput,
        IndexName: 'UserIndex',
        KeyConditionExpression: 'user_id = :userId',
        ExpressionAttributeValues: {
          ':userId': userId
        },
        ScanIndexForward: false // Sort by created_at descending
      };
    } else if (status) {
      // Query by status using StatusIndex
      queryInput = {
        ...queryInput,
        IndexName: 'StatusIndex',
        KeyConditionExpression: '#status = :status',
        FilterExpression: 'user_id = :userId',
        ExpressionAttributeNames: {
          '#status': 'status'
        },
        ExpressionAttributeValues: {
          ':status': status,
          ':userId': userId
        },
        ScanIndexForward: false
      };
    } else if (category) {
      // Query by category using CategoryIndex
      queryInput = {
        ...queryInput,
        IndexName: 'CategoryIndex',
        KeyConditionExpression: 'category = :category',
        FilterExpression: 'user_id = :userId',
        ExpressionAttributeValues: {
          ':category': category,
          ':userId': userId
        },
        ScanIndexForward: false
      };
    }

    // Query items from DynamoDB
    const result = await docClient.send(new QueryCommand(queryInput));

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        items: result.Items || [],
        count: result.Count,
        scannedCount: result.ScannedCount
      })
    };
  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        message: 'Internal server error',
        error: error.message
      })
    };
  }
};
