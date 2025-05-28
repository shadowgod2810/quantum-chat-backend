#!/usr/bin/env pwsh
# QuantumChat Backend Deployment Script for AWS EC2

# Function to handle errors and provide consistent output
function Write-StepLog {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$ForegroundColor = "Yellow",
        
        [Parameter(Mandatory=$false)]
        [switch]$IsError
    )
    
    if ($IsError) {
        Write-Host "[ERROR] $Message" -ForegroundColor Red
    } else {
        Write-Host "[INFO] $Message" -ForegroundColor $ForegroundColor
    }
}

# Function to execute SSH commands with error handling
function Invoke-RemoteCommand {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Command,
        
        [Parameter(Mandatory=$false)]
        [string]$ErrorMessage = "Failed to execute remote command"
    )
    
    try {
        $sshCommand = "ssh -i `"$SSH_KEY_PATH`" -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_INSTANCE_IP} `"$Command`""
        Write-StepLog "Executing: $sshCommand" -ForegroundColor Gray
        $result = Invoke-Expression $sshCommand
        if ($LASTEXITCODE -ne 0) {
            Write-StepLog "$ErrorMessage (Exit code: $LASTEXITCODE)" -IsError
            return $false
        }
        return $true
    } catch {
        Write-StepLog "$ErrorMessage. Exception: $_" -IsError
        return $false
    }
}

# Function to copy files to remote server with error handling
function Copy-ToRemoteServer {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory=$false)]
        [string]$ErrorMessage = "Failed to copy file to remote server"
    )
    
    try {
        $scpCommand = "scp -i `"$SSH_KEY_PATH`" -o StrictHostKeyChecking=no `"$SourcePath`" ${EC2_USER}@${EC2_INSTANCE_IP}:`"$DestinationPath`""
        Write-StepLog "Executing: $scpCommand" -ForegroundColor Gray
        $result = Invoke-Expression $scpCommand
        if ($LASTEXITCODE -ne 0) {
            Write-StepLog "$ErrorMessage (Exit code: $LASTEXITCODE)" -IsError
            return $false
        }
        return $true
    } catch {
        Write-StepLog "$ErrorMessage. Exception: $_" -IsError
        return $false
    }
}

# Start deployment process
Write-StepLog "Starting QuantumChat backend deployment to AWS EC2..." -ForegroundColor Cyan

# Configuration - Update these values
$EC2_INSTANCE_IP = "13.203.216.60"
$EC2_USER = "ec2-user"  # Usually ec2-user for Amazon Linux or ubuntu for Ubuntu
$SSH_KEY_PATH = "C:\Users\91862\quantum-chat-key.pem"
$REMOTE_APP_DIR = "/home/$EC2_USER/quantum-chat-backend"
$RDS_ENDPOINT = "quantum-chat-db.crcwi8woqrfw.ap-south-1.rds.amazonaws.com"
$RDS_DB_NAME = "quantumchat"
$RDS_USERNAME = "MegaProject"
$RDS_PASSWORD = "Harsh2028"

# Step 1: Verify SSH connectivity
Write-StepLog "Verifying SSH connectivity..." 
if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Write-StepLog "SSH not found. Please install OpenSSH to deploy to AWS EC2." -IsError
    exit 1
}

# Test SSH connection
$sshTestResult = Invoke-RemoteCommand -Command "echo 'SSH connection successful'" -ErrorMessage "Failed to connect to EC2 instance"
if (-not $sshTestResult) {
    Write-StepLog "Please check your SSH key path and EC2 instance details." -IsError
    exit 1
}

# Step 2: Prepare local environment
Write-StepLog "Preparing local environment..."

# Create a temporary deployment directory
$tempDeployDir = Join-Path -Path (Get-Location).Path -ChildPath "deploy_temp"
Write-StepLog "Creating temporary directory at: $tempDeployDir"
if (Test-Path $tempDeployDir) { 
    Write-StepLog "Removing existing temporary directory"
    Remove-Item -Path $tempDeployDir -Recurse -Force 
}
New-Item -Path $tempDeployDir -ItemType Directory -Force | Out-Null

# Verify the temporary directory was created
if (-not (Test-Path $tempDeployDir)) {
    Write-StepLog "Failed to create temporary directory at $tempDeployDir" -IsError
    exit 1
}

# Copy necessary files to deployment directory
Write-StepLog "Copying application files to deployment directory..."
$filesToCopy = @(
    "*.py",
    "requirements.txt",
    "static/**",
    "templates/**",
    "models/**",
    "routes/**",
    "utils/**"
)

# Get the current directory
$currentDir = Get-Location
Write-StepLog "Current directory: $currentDir"

# List files in current directory for debugging
Write-StepLog "Files in current directory:"
$filesInDir = Get-ChildItem -Path $currentDir
foreach ($file in $filesInDir) {
    Write-StepLog "  - $($file.Name)"
}

# Copy files to temp directory
foreach ($pattern in $filesToCopy) {
    Write-StepLog "Looking for files matching pattern: $pattern"
    $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
    
    if ($files) {
        Write-StepLog "Found $($files.Count) files/directories matching $pattern"
        foreach ($file in $files) {
            $targetPath = Join-Path -Path $tempDeployDir -ChildPath $file.Name
            Write-StepLog "  Copying $($file.FullName) to $targetPath"
            
            if ($file -is [System.IO.DirectoryInfo]) {
                Copy-Item -Path $file.FullName -Destination $targetPath -Recurse -Force
            } else {
                Copy-Item -Path $file.FullName -Destination $targetPath -Force
            }
        }
    } else {
        Write-StepLog "No files found matching pattern: $pattern" -ForegroundColor Yellow
    }
}

# Verify requirements.txt exists in deployment directory
$requirementsPath = Join-Path -Path $tempDeployDir -ChildPath "requirements.txt"
Write-StepLog "Checking for requirements.txt at: $requirementsPath"

if (-not (Test-Path $requirementsPath)) {
    Write-StepLog "requirements.txt not found. Creating a basic one..." -ForegroundColor Yellow
    @"
flask==2.0.1
gunicorn==20.1.0
psycopg2-binary==2.9.1
flask-socketio==5.1.1
python-dotenv==0.19.0
"@ | Out-File -FilePath $requirementsPath -Encoding utf8
    
    # Verify the file was created
    if (Test-Path $requirementsPath) {
        Write-StepLog "Successfully created requirements.txt" -ForegroundColor Green
    } else {
        Write-StepLog "Failed to create requirements.txt" -IsError
        exit 1
    }
}

# Verify app.py exists in deployment directory
$appPyPath = Join-Path -Path $tempDeployDir -ChildPath "app.py"
Write-StepLog "Checking for app.py at: $appPyPath"

if (-not (Test-Path $appPyPath)) {
    Write-StepLog "app.py not found. Creating a basic one..." -ForegroundColor Yellow
    @"
import os
from flask import Flask, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Configure logging
log_level = os.getenv('LOG_LEVEL', 'INFO')
logging.basicConfig(level=getattr(logging, log_level))
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')

# Configure CORS
cors_origins = os.getenv('CORS_ORIGINS', '*').split(',')
CORS(app, resources={r"/*": {"origins": cors_origins}})

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins=cors_origins)

# Database initialization function
def init_database():
    logger.info("Initializing database...")
    # Add your database initialization code here
    logger.info("Database initialized successfully")

# Routes
@app.route('/')
def index():
    return jsonify({
        "status": "success",
        "message": "QuantumChat API is running"
    })

@app.route('/api/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "version": "1.0.0"
    })

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('message')
def handle_message(data):
    logger.info(f"Received message: {data}")
    # Process the message and broadcast to other clients
    socketio.emit('message', data, skip_sid=request.sid)

# Main entry point
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEV_MODE', 'false').lower() == 'true'
    
    # Initialize database on startup
    init_database()
    
    # Start the server
    socketio.run(app, host='0.0.0.0', port=port, debug=debug)
"@ | Out-File -FilePath $appPyPath -Encoding utf8
    
    # Verify the file was created
    if (Test-Path $appPyPath) {
        Write-StepLog "Successfully created app.py" -ForegroundColor Green
    } else {
        Write-StepLog "Failed to create app.py" -IsError
        exit 1
    }
}

# Step 3: Create deployment package
Write-StepLog "Creating deployment package..."
$deploymentZip = Join-Path -Path (Get-Location).Path -ChildPath "quantum-chat-backend.zip"
Write-StepLog "Deployment zip path: $deploymentZip"

# Check if the zip file already exists and remove it
if (Test-Path $deploymentZip) { 
    Write-StepLog "Removing existing zip file..."
    Remove-Item $deploymentZip -Force 
}

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Write-StepLog "Creating zip from directory: $tempDeployDir to $deploymentZip"
    [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDeployDir, $deploymentZip)
    
    # Verify zip file was created successfully
    if (-not (Test-Path $deploymentZip)) {
        throw "Failed to create deployment package - zip file not found after creation"
    }
    
    $zipFileInfo = Get-Item $deploymentZip
    Write-StepLog "Deployment package created: $($zipFileInfo.FullName) (Size: $($zipFileInfo.Length) bytes)" -ForegroundColor Green
} catch {
    Write-StepLog "Failed to create deployment package: $_" -IsError
    exit 1
}

# Step 4: Deploy to AWS EC2
Write-StepLog "Deploying to AWS EC2..." -ForegroundColor Cyan

# Create remote directory if it doesn't exist
Write-StepLog "Creating remote directory..."
Invoke-RemoteCommand -Command "mkdir -p $REMOTE_APP_DIR" -ErrorMessage "Failed to create remote directory"

# Copy deployment package to EC2 instance
Write-StepLog "Copying deployment package to EC2 instance..."
$copyResult = Copy-ToRemoteServer -SourcePath $deploymentZip -DestinationPath "$REMOTE_APP_DIR/$deploymentZip" -ErrorMessage "Failed to copy deployment package"
if (-not $copyResult) {
    Write-StepLog "Deployment failed. Could not copy files to EC2 instance." -IsError
    exit 1
}

# Verify the zip file exists on the remote server before extracting
Write-StepLog "Verifying deployment package on remote server..."
$verifyZipResult = Invoke-RemoteCommand -Command "ls -la $REMOTE_APP_DIR/$deploymentZip" -ErrorMessage "Deployment package not found on remote server"
if (-not $verifyZipResult) {
    Write-StepLog "Deployment failed. Zip file not found on remote server." -IsError
    exit 1
}

# Extract deployment package on EC2 instance
Write-StepLog "Extracting deployment package on EC2 instance..."
$extractResult = Invoke-RemoteCommand -Command "cd $REMOTE_APP_DIR && unzip -o $deploymentZip && rm $deploymentZip" -ErrorMessage "Failed to extract deployment package"
if (-not $extractResult) {
    Write-StepLog "Deployment failed. Could not extract files on EC2 instance." -IsError
    exit 1
}

# Verify key files exist after extraction
Write-StepLog "Verifying extracted files..."
$verifyFilesResult = Invoke-RemoteCommand -Command "ls -la $REMOTE_APP_DIR/requirements.txt $REMOTE_APP_DIR/app.py" -ErrorMessage "Required files not found after extraction"
if (-not $verifyFilesResult) {
    Write-StepLog "Deployment failed. Required files missing after extraction." -IsError
    exit 1
}

# Set up Python environment on EC2 instance
Write-StepLog "Setting up Python environment on EC2 instance..."
$setupPythonResult = Invoke-RemoteCommand -Command "cd $REMOTE_APP_DIR && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt --no-cache-dir" -ErrorMessage "Failed to set up Python environment"
if (-not $setupPythonResult) {
    Write-StepLog "Deployment failed. Could not set up Python environment." -IsError
    exit 1
}

# Create or update environment file
Write-StepLog "Creating environment file on EC2 instance..."
$envContent = @"
FLASK_ENV=production
DEV_MODE=false
PORT=5000
DATABASE_URL=postgresql://${RDS_USERNAME}:${RDS_PASSWORD}@${RDS_ENDPOINT}:5432/${RDS_DB_NAME}
SECRET_KEY=$(New-Guid)
CORS_ORIGINS=https://quantum-chat-frontend.s3-website-ap-south-1.amazonaws.com
LOG_LEVEL=ERROR
"@

$envContent | Out-File -FilePath ".env.tmp" -Encoding utf8
$copyEnvResult = Copy-ToRemoteServer -SourcePath ".env.tmp" -DestinationPath "$REMOTE_APP_DIR/.env" -ErrorMessage "Failed to copy environment file"
Remove-Item ".env.tmp" -Force
if (-not $copyEnvResult) {
    Write-StepLog "Deployment failed. Could not create environment file." -IsError
    exit 1
}

# Set up systemd service for the application
Write-StepLog "Setting up systemd service..."
$serviceContent = @"
[Unit]
Description=QuantumChat Backend Service
After=network.target

[Service]
User=$EC2_USER
WorkingDirectory=$REMOTE_APP_DIR
EnvironmentFile=$REMOTE_APP_DIR/.env
ExecStart=$REMOTE_APP_DIR/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
"@

$serviceContent | Out-File -FilePath "quantum-chat.service.tmp" -Encoding utf8
$copyServiceResult = Copy-ToRemoteServer -SourcePath "quantum-chat.service.tmp" -DestinationPath "$REMOTE_APP_DIR/quantum-chat.service" -ErrorMessage "Failed to copy service file"
Remove-Item "quantum-chat.service.tmp" -Force
if (-not $copyServiceResult) {
    Write-StepLog "Deployment failed. Could not create systemd service file." -IsError
    exit 1
}

# Install and start the service
Write-StepLog "Installing and starting the service..."
$startServiceResult = Invoke-RemoteCommand -Command "sudo mv $REMOTE_APP_DIR/quantum-chat.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable quantum-chat && sudo systemctl restart quantum-chat" -ErrorMessage "Failed to install or start service"
if (-not $startServiceResult) {
    Write-StepLog "Deployment failed. Could not start the service." -IsError
    exit 1
}

# Check if the service is running
Write-StepLog "Checking service status..."
$serviceStatusResult = Invoke-RemoteCommand -Command "sudo systemctl status quantum-chat" -ErrorMessage "Failed to check service status"
if (-not $serviceStatusResult) {
    Write-StepLog "Service may not be running correctly. Please check manually." -ForegroundColor Yellow
}

# Initialize the database
Write-StepLog "Initializing the database..."
$initDbResult = Invoke-RemoteCommand -Command "cd $REMOTE_APP_DIR && source venv/bin/activate && python -c 'from app import init_database; init_database()'" -ErrorMessage "Failed to initialize database"
if (-not $initDbResult) {
    Write-StepLog "Database initialization failed. Please check your database connection." -IsError
}

# Clean up temporary files
Write-StepLog "Cleaning up temporary files..."
Remove-Item -Path $tempDeployDir -Recurse -Force
Remove-Item -Path $deploymentZip -Force

# Provide instructions for setting up Nginx
Write-StepLog "\nTo set up Nginx as a reverse proxy:" -ForegroundColor Cyan
Write-Host "1. SSH into your EC2 instance: ssh -i $SSH_KEY_PATH $EC2_USER@$EC2_INSTANCE_IP" -ForegroundColor Yellow
Write-Host "2. Install Nginx: sudo apt-get update && sudo apt-get install -y nginx" -ForegroundColor Yellow
Write-Host "3. Create Nginx config: sudo nano /etc/nginx/sites-available/quantum-chat" -ForegroundColor Yellow
Write-Host "4. Add the following configuration:" -ForegroundColor Yellow
Write-Host @"
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
"@ -ForegroundColor Gray
Write-Host "5. Enable the site: sudo ln -s /etc/nginx/sites-available/quantum-chat /etc/nginx/sites-enabled/" -ForegroundColor Yellow
Write-Host "6. Test and restart Nginx: sudo nginx -t && sudo systemctl restart nginx" -ForegroundColor Yellow
Write-Host "7. Set up SSL with Let's Encrypt: sudo apt-get install -y certbot python3-certbot-nginx && sudo certbot --nginx -d your-domain.com" -ForegroundColor Yellow

Write-StepLog "Deployment to AWS EC2 completed!" -ForegroundColor Green
Write-StepLog "Your API is now running at: http://$EC2_INSTANCE_IP:5000" -ForegroundColor Green
Write-StepLog "Deployment process completed!" -ForegroundColor Green
