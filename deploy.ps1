#!/usr/bin/env pwsh
# QuantumChat Frontend Deployment Script for AWS S3

Write-Host "🚀 Starting QuantumChat frontend deployment to AWS S3..." -ForegroundColor Cyan

# Configuration - Update these values
$S3_BUCKET_NAME = "quantum-chat-frontend"
$CLOUDFRONT_DISTRIBUTION_ID = "" # Optional, if using CloudFront
$AWS_REGION = "ap-south-1" # Change to your preferred region

# Step 0: Ensure .env.production is present with correct API endpoints
$envFilePath = ".env.production"
if (-not (Test-Path -Path $envFilePath)) {
    Write-Host "Creating .env.production file..." -ForegroundColor Yellow
    @"
# Production environment variables
VITE_APP_API_URL=https://quantum-chat-api.onrender.com
VITE_APP_SOCKET_URL=https://quantum-chat-api.onrender.com
VITE_APP_ENV=production
VITE_APP_DEBUG_MODE=false
VITE_APP_VERSION=1.0.0
VITE_APP_ENCRYPTION_ENABLED=true
VITE_APP_MAX_MESSAGE_LENGTH=10000
VITE_APP_ENABLE_ANALYTICS=true
VITE_APP_STORAGE_PREFIX=quantum_chat_prod_
VITE_APP_SESSION_TIMEOUT=3600000
"@ | Out-File -FilePath $envFilePath -Encoding utf8
    Write-Host ".env.production created." -ForegroundColor Green
} else {
    Write-Host ".env.production already exists. Skipping creation." -ForegroundColor Cyan
}

# Step 1: Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
npm ci

# Step 2: Run linting and type checking
Write-Host "🔍 Running linting and type checking..." -ForegroundColor Yellow
npm run lint
npm run type-check

# Step 3: Build for production
Write-Host "🏗️  Building for production..." -ForegroundColor Yellow
npm run build

# Step 4: Deploy to AWS S3
Write-Host "🌐 Deploying to AWS S3..." -ForegroundColor Yellow

# Try to find AWS CLI in common installation paths
$awsCliPaths = @(
    "$env:ProgramFiles\Amazon\AWSCLIV2\aws.exe",
    "$env:ProgramFiles (x86)\Amazon\AWSCLIV2\aws.exe",
    "$env:USERPROFILE\AppData\Local\Programs\Python\Python*\Scripts\aws.exe",
    "$env:USERPROFILE\AppData\Local\Amazon\AWSCLIV2\aws.exe"
)

$awsCliPath = $null
foreach ($path in $awsCliPaths) {
    $resolvedPaths = Resolve-Path -Path $path -ErrorAction SilentlyContinue
    if ($resolvedPaths) {
        $awsCliPath = $resolvedPaths[0].Path
        break
    }
}

# If AWS CLI is found
if ((Get-Command aws -ErrorAction SilentlyContinue) -or $awsCliPath) {
    $awsCommand = if ($awsCliPath) { $awsCliPath } else { "aws" }

    # Upload build files to S3
    Write-Host "☁️  Uploading files to S3 bucket: $S3_BUCKET_NAME" -ForegroundColor Yellow
    & $awsCommand s3 sync ./dist s3://$S3_BUCKET_NAME --delete --region $AWS_REGION

    # Ensure correct content-type for HTML
    Write-Host "📄 Setting content-type for index.html..." -ForegroundColor Yellow
    & $awsCommand s3 cp s3://$S3_BUCKET_NAME/index.html s3://$S3_BUCKET_NAME/index.html --content-type "text/html" --metadata-directive REPLACE --region $AWS_REGION

    # Invalidate CloudFront if configured
    if ($CLOUDFRONT_DISTRIBUTION_ID) {
        Write-Host "🧹 Invalidating CloudFront cache..." -ForegroundColor Yellow
        & $awsCommand cloudfront create-invalidation --distribution-id $CLOUDFRONT_DISTRIBUTION_ID --paths "/*" --region $AWS_REGION
    }

    Write-Host "✅ Deployment to AWS S3 completed!" -ForegroundColor Green
    Write-Host "🌍 Your site is available at: http://$S3_BUCKET_NAME.s3-website-$AWS_REGION.amazonaws.com" -ForegroundColor Cyan

    if (-not $CLOUDFRONT_DISTRIBUTION_ID) {
        Write-Host "`n⚙️  To set up CloudFront:" -ForegroundColor Yellow
        Write-Host "1. Go to AWS CloudFront Console" -ForegroundColor Yellow
        Write-Host "2. Create a new distribution with S3 bucket as the origin" -ForegroundColor Yellow
        Write-Host "3. Enable HTTPS, configure cache settings" -ForegroundColor Yellow
        Write-Host "4. Add CLOUDFRONT_DISTRIBUTION_ID to this script for future deployments" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ AWS CLI not found. Please install it first." -ForegroundColor Red
    Write-Host "🔗 https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html" -ForegroundColor Cyan
}

Write-Host "🎉 Deployment process completed!" -ForegroundColor Green
