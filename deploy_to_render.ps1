# PowerShell script to deploy to Render
Write-Host "Preparing to deploy backend to Render..." -ForegroundColor Green

# Check if the pqcrypto directory exists in the backend folder
if (-not (Test-Path -Path "pqcrypto")) {
    Write-Host "Copying custom pqcrypto library to backend folder..." -ForegroundColor Yellow
    
    # Create the pqcrypto directory if it doesn't exist
    New-Item -ItemType Directory -Path "pqcrypto" -Force | Out-Null
    
    # Copy the pqcrypto library files
    Copy-Item -Path "..\pqcrypto\*" -Destination "pqcrypto" -Recurse -Force
    
    Write-Host "Custom pqcrypto library copied successfully." -ForegroundColor Green
}

# Check if Git is initialized
if (-not (Test-Path -Path ".git")) {
    Write-Host "Initializing Git repository..." -ForegroundColor Yellow
    git init
    git add .
    git commit -m "Initial commit for Render deployment"
}

# Create a .gitignore file if it doesn't exist
if (-not (Test-Path -Path ".gitignore")) {
    Write-Host "Creating .gitignore file..." -ForegroundColor Yellow
    @"
__pycache__/
*.py[cod]
*$py.class
*.so
.env
.env.local
venv/
ENV/
.vscode/
*.sqlite
*.db
"@ | Out-File -FilePath ".gitignore" -Encoding utf8
}

# Check if Render CLI is installed
$renderCliInstalled = $null -ne (Get-Command "render" -ErrorAction SilentlyContinue)
if (-not $renderCliInstalled) {
    Write-Host "Render CLI not found. Please install it first or deploy manually through the Render dashboard." -ForegroundColor Yellow
    Write-Host "Visit https://render.com/docs/cli to install the Render CLI." -ForegroundColor Yellow
    
    # Open the Render dashboard
    Start-Process "https://dashboard.render.com/new/web-service"
    
    Write-Host "Follow these steps to deploy manually:" -ForegroundColor Cyan
    Write-Host "1. Sign in to your Render account" -ForegroundColor White
    Write-Host "2. Click 'New Web Service'" -ForegroundColor White
    Write-Host "3. Connect your GitHub/GitLab repository or use the 'Public Git repository' option" -ForegroundColor White
    Write-Host "4. Enter the repository URL" -ForegroundColor White
    Write-Host "5. Configure with these settings:" -ForegroundColor White
    Write-Host "   - Name: quantum-chat-api" -ForegroundColor White
    Write-Host "   - Runtime: Python" -ForegroundColor White
    Write-Host "   - Build Command: pip install -r requirements.txt" -ForegroundColor White
    Write-Host "   - Start Command: gunicorn --worker-class eventlet -w 1 app:app" -ForegroundColor White
    Write-Host "6. Add the following environment variables:" -ForegroundColor White
    Write-Host "   - FLASK_ENV: production" -ForegroundColor White
    Write-Host "   - DEV_MODE: false" -ForegroundColor White
    Write-Host "   - DATABASE_PATH: /opt/render/project/src/data/backend_database.sqlite" -ForegroundColor White
    Write-Host "7. Add a disk with:" -ForegroundColor White
    Write-Host "   - Name: sqlite-data" -ForegroundColor White
    Write-Host "   - Mount Path: /opt/render/project/src/data" -ForegroundColor White
    Write-Host "   - Size: 1 GB" -ForegroundColor White
    Write-Host "8. Click 'Create Web Service'" -ForegroundColor White
} else {
    # Deploy using Render CLI
    Write-Host "Deploying to Render using CLI..." -ForegroundColor Green
    render blueprint apply
}

Write-Host "Deployment preparation complete!" -ForegroundColor Green
Write-Host "Your backend API will be available at: https://quantum-chat-api.onrender.com" -ForegroundColor Cyan
