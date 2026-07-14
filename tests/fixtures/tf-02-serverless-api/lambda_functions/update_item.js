const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, UpdateCommand, GetCommand } = require('@aws-sdk/lib-dynamodb');

const client = new DynamoDBClient({ region: process.env.REGION });
const docClient = DynamoDBDocumentClient.from(client);

exports.handler = async (event) => {
  console.log('Event:', JSON.stringify(event, null, 2));

  try {
    // Extract item ID from path parameters
    const itemId = event.pathParameters?.id;

    if (!itemId) {
      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({ message: 'Missing item ID' })
      };
    }

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

    // Parse request body
    const body = JSON.parse(event.body || '{}');

    // First, verify the item exists and user owns it
    const getResult = await docClient.send(new GetCommand({
      TableName: process.env.TABLE_NAME,
      Key: {
        id: itemId
      }
    }));

    if (!getResult.Item) {
      return {
        statusCode: 404,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({ message: 'Item not found' })
      };
    }

    if (getResult.Item.user_id !== userId) {
      return {
        statusCode: 403,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({ message: 'Forbidden' })
      };
    }

    // Build update expression
    const updateExpressions = [];
    const expressionAttributeNames = {};
    const expressionAttributeValues = {};

    if (body.title) {
      updateExpressions.push('#title = :title');
      expressionAttributeNames['#title'] = 'title';
      expressionAttributeValues[':title'] = body.title;
    }

    if (body.description !== undefined) {
      updateExpressions.push('#description = :description');
      expressionAttributeNames['#description'] = 'description';
      expressionAttributeValues[':description'] = body.description;
    }

    if (body.category) {
      updateExpressions.push('#category = :category');
      expressionAttributeNames['#category'] = 'category';
      expressionAttributeValues[':category'] = body.category;
    }

    if (body.status) {
      updateExpressions.push('#status = :status');
      expressionAttributeNames['#status'] = 'status';
      expressionAttributeValues[':status'] = body.status;
    }

    // Always update the updated_at timestamp
    updateExpressions.push('#updated_at = :updated_at');
    expressionAttributeNames['#updated_at'] = 'updated_at';
    expressionAttributeValues[':updated_at'] = Date.now();

    if (updateExpressions.length === 1) {
      // Only updated_at would be updated
      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({ message: 'No fields to update' })
      };
    }

    // Update item in DynamoDB
    const result = await docClient.send(new UpdateCommand({
      TableName: process.env.TABLE_NAME,
      Key: {
        id: itemId
      },
      UpdateExpression: 'SET ' + updateExpressions.join(', '),
      ExpressionAttributeNames: expressionAttributeNames,
      ExpressionAttributeValues: expressionAttributeValues,
      ReturnValues: 'ALL_NEW'
    }));

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        message: 'Item updated successfully',
        item: result.Attributes
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
