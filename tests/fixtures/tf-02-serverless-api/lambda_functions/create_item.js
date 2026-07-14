const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, PutCommand } = require('@aws-sdk/lib-dynamodb');
const { randomUUID } = require('crypto');

const client = new DynamoDBClient({ region: process.env.REGION });
const docClient = DynamoDBDocumentClient.from(client);

exports.handler = async (event) => {
  console.log('Event:', JSON.stringify(event, null, 2));

  try {
    // Parse request body
    const body = JSON.parse(event.body || '{}');

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

    // Validate required fields
    if (!body.title || !body.category) {
      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
          message: 'Missing required fields: title, category'
        })
      };
    }

    // Create item
    const timestamp = Date.now();
    const item = {
      id: randomUUID(),
      user_id: userId,
      title: body.title,
      description: body.description || '',
      category: body.category,
      status: body.status || 'active',
      created_at: timestamp,
      updated_at: timestamp,
      ttl: body.ttl || Math.floor(Date.now() / 1000) + (90 * 24 * 60 * 60) // 90 days default
    };

    // Put item in DynamoDB
    await docClient.send(new PutCommand({
      TableName: process.env.TABLE_NAME,
      Item: item
    }));

    return {
      statusCode: 201,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        message: 'Item created successfully',
        item
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
