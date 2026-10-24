#!/bin/bash
set -euo pipefail

# === CONFIG ===
PROJECT_ID="${GCP_PROJECT_ID:?Set GCP_PROJECT_ID}"
REGION="${GCP_REGION:-europe-west1}"
BACKEND_IMAGE="gcr.io/${PROJECT_ID}/iot-scanner-backend"
FRONTEND_IMAGE="gcr.io/${PROJECT_ID}/iot-scanner-frontend"

echo "=== Deploying IoT Scanner to GCP Cloud Run ==="
echo "Project: ${PROJECT_ID}"
echo "Region:  ${REGION}"

# Enable required APIs
echo "--- Enabling APIs ---"
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  redis.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  --project="${PROJECT_ID}" --quiet

# Build & push backend
echo "--- Building backend ---"
gcloud builds submit ./backend \
  --tag "${BACKEND_IMAGE}" \
  --project="${PROJECT_ID}" \
  --dockerfile=Dockerfile.cloudrun \
  --quiet

# Build & push frontend (API URL will be set after backend deploys)
echo "--- Building frontend ---"
gcloud builds submit ./frontend \
  --tag "${FRONTEND_IMAGE}" \
  --project="${PROJECT_ID}" \
  --dockerfile=Dockerfile.cloudrun \
  --quiet

# Deploy backend to Cloud Run
echo "--- Deploying backend ---"
gcloud run deploy iot-scanner-api \
  --image="${BACKEND_IMAGE}" \
  --region="${REGION}" \
  --platform=managed \
  --allow-unauthenticated \
  --memory=512Mi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=3 \
  --set-env-vars="SHODAN_API_KEY=${SHODAN_API_KEY},CENSYS_API_KEY=${CENSYS_API_KEY}" \
  --set-env-vars="DATABASE_URL=${DATABASE_URL}" \
  --set-env-vars="REDIS_URL=${REDIS_URL}" \
  --project="${PROJECT_ID}" \
  --quiet

BACKEND_URL=$(gcloud run services describe iot-scanner-api \
  --region="${REGION}" --project="${PROJECT_ID}" \
  --format='value(status.url)')
echo "Backend URL: ${BACKEND_URL}"

# Rebuild frontend with actual backend URL
echo "--- Rebuilding frontend with backend URL ---"
gcloud builds submit ./frontend \
  --tag "${FRONTEND_IMAGE}" \
  --project="${PROJECT_ID}" \
  --dockerfile=Dockerfile.cloudrun \
  --substitutions="_VITE_API_URL=${BACKEND_URL}" \
  --quiet

# Deploy frontend to Cloud Run
echo "--- Deploying frontend ---"
gcloud run deploy iot-scanner-dashboard \
  --image="${FRONTEND_IMAGE}" \
  --region="${REGION}" \
  --platform=managed \
  --allow-unauthenticated \
  --memory=256Mi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=2 \
  --project="${PROJECT_ID}" \
  --quiet

FRONTEND_URL=$(gcloud run services describe iot-scanner-dashboard \
  --region="${REGION}" --project="${PROJECT_ID}" \
  --format='value(status.url)')

echo ""
echo "=== DEPLOYED ==="
echo "Dashboard: ${FRONTEND_URL}"
echo "API:       ${BACKEND_URL}"
echo "API Docs:  ${BACKEND_URL}/docs"
