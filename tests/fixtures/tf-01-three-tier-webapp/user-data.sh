#!/bin/bash
set -e

# Update system packages
dnf update -y

# Install required packages
dnf install -y \
    amazon-cloudwatch-agent \
    amazon-ssm-agent \
    httpd \
    php \
    php-mysqlnd \
    php-fpm \
    php-json \
    mariadb105

# Start and enable services
systemctl start httpd
systemctl enable httpd
systemctl start amazon-ssm-agent
systemctl enable amazon-ssm-agent

# Configure CloudWatch Agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<'EOF'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/httpd/access_log",
            "log_group_name": "/aws/ec2/${project_name}-${environment}/httpd-access",
            "log_stream_name": "{instance_id}"
          },
          {
            "file_path": "/var/log/httpd/error_log",
            "log_group_name": "/aws/ec2/${project_name}-${environment}/httpd-error",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  },
  "metrics": {
    "namespace": "${project_name}-${environment}",
    "metrics_collected": {
      "mem": {
        "measurement": [
          {
            "name": "mem_used_percent",
            "rename": "MemoryUsedPercent",
            "unit": "Percent"
          }
        ],
        "metrics_collection_interval": 60
      },
      "disk": {
        "measurement": [
          {
            "name": "used_percent",
            "rename": "DiskUsedPercent",
            "unit": "Percent"
          }
        ],
        "metrics_collection_interval": 60,
        "resources": [
          "/"
        ]
      }
    }
  }
}
EOF

# Start CloudWatch Agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -s \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json

# Create sample PHP application
cat > /var/www/html/index.php <<'PHPEOF'
<?php
$instance_id = file_get_contents('http://169.254.169.254/latest/meta-data/instance-id');
$az = file_get_contents('http://169.254.169.254/latest/meta-data/placement/availability-zone');
$instance_type = file_get_contents('http://169.254.169.254/latest/meta-data/instance-type');

$db_host = getenv('DB_ENDPOINT') ?: 'localhost';
$db_name = getenv('DB_NAME') ?: '${db_name}';

echo "<html><head><title>${project_name} - ${environment}</title>";
echo "<style>body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }";
echo ".container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }";
echo "h1 { color: #333; } .info { margin: 10px 0; padding: 10px; background: #e8f4f8; border-left: 4px solid #0066cc; }";
echo ".success { background: #d4edda; border-left-color: #28a745; } .error { background: #f8d7da; border-left-color: #dc3545; }";
echo "</style></head><body>";
echo "<div class='container'>";
echo "<h1>${project_name} - ${environment}</h1>";
echo "<div class='info'><strong>Instance ID:</strong> " . $instance_id . "</div>";
echo "<div class='info'><strong>Availability Zone:</strong> " . $az . "</div>";
echo "<div class='info'><strong>Instance Type:</strong> " . $instance_type . "</div>";
echo "<div class='info'><strong>Database Host:</strong> " . $db_host . "</div>";

// Database connection test
try {
    $dsn = "mysql:host=" . str_replace(':3306', '', $db_host) . ";dbname=" . $db_name;
    $pdo = new PDO($dsn, '${db_username}', '${db_password}');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "<div class='info success'><strong>Database Status:</strong> Connected successfully!</div>";
} catch (PDOException $e) {
    echo "<div class='info error'><strong>Database Status:</strong> Connection failed - " . $e->getMessage() . "</div>";
}

echo "<div class='info'><strong>Server Time:</strong> " . date('Y-m-d H:i:s T') . "</div>";
echo "</div></body></html>";
?>
PHPEOF

# Create health check endpoint
cat > /var/www/html/health <<'HEALTHEOF'
<?php
http_response_code(200);
echo json_encode([
    'status' => 'healthy',
    'timestamp' => time(),
    'instance_id' => file_get_contents('http://169.254.169.254/latest/meta-data/instance-id')
]);
?>
HEALTHEOF

# Set environment variables for PHP
cat > /etc/environment <<EOF
DB_ENDPOINT=${db_endpoint}
DB_NAME=${db_name}
AWS_REGION=${region}
PROJECT_NAME=${project_name}
ENVIRONMENT=${environment}
EOF

# Configure PHP to use environment variables
echo "variables_order = \"EGPCS\"" >> /etc/php.ini

# Set proper permissions
chown -R apache:apache /var/www/html
chmod -R 755 /var/www/html

# Restart Apache
systemctl restart httpd

# Signal completion
echo "User data script completed successfully" > /var/log/user-data-status.log
