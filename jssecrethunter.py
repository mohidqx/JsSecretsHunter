#!/usr/bin/env python3
"""
JSSecretHunter - Production-Grade JavaScript Secret Scanner
Author  : TeamCyberOps
License : MIT
"""

import re
import sys
import json
import time
import argparse
import logging
import hashlib
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from typing import Optional

# ─────────────────────────────────────────────
# REGEX PATTERNS  (617 patterns)
# ─────────────────────────────────────────────
_regex = {
    'google_api_key'                     : r'AIza[0-9A-Za-z\-_]{35}',
    'google_captcha_v2'                  : r'6L[0-9A-Za-z\-_]{38}',
    'google_oauth_token'                 : r'ya29\.[0-9A-Za-z\-_]+',
    'google_oauth_client_id'             : r'[0-9]{12}\-[0-9a-z]{32}\.apps\.googleusercontent\.com',
    'google_oauth_client_secret'         : r'GOCSPX\-[0-9A-Za-z\-_]{28}',
    'google_service_account'             : r'"type"\s*:\s*"service_account"',
    'google_firebase_url'                : r'[a-z0-9.-]+\.firebaseio\.com',
    'google_refresh_token'               : r'1//[0-9A-Za-z\-_]{40,}',
    'gcp_service_account_email'          : r'[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com',
    'google_cloud_private_key'           : r'-----BEGIN PRIVATE KEY-----',
    'amazon_aws_access_key_id'           : r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
    'amazon_aws_secret_access_key'       : r'(?i)aws.{0,20}?(?:secret|key).{0,20}?[=:"\s][0-9a-zA-Z/+]{40}',
    'amazon_mws_auth_token'              : r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url'                     : r's3\.amazonaws\.com[/]+|[a-zA-Z0-9_\-]*\.s3\.amazonaws\.com',
    'amazon_cognito_pool_id'             : r'[a-z]{2}-[a-z]+-[0-9]:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_ecr'                     : r'[0-9]{12}\.dkr\.ecr\.[a-z0-9\-]+\.amazonaws\.com',
    'amazon_aws_rds_endpoint'            : r'[a-z0-9\-]+\.[a-z0-9]{12}\.[a-z]{2}-[a-z]+-[0-9]\.rds\.amazonaws\.com',
    'amazon_aws_sqs_url'                 : r'https://sqs\.[a-z0-9\-]+\.amazonaws\.com/[0-9]+/[a-zA-Z0-9\-_]+',
    'amazon_aws_sns_arn'                 : r'arn:aws:sns:[a-z0-9\-]+:[0-9]{12}:[a-zA-Z0-9\-_]+',
    'amazon_aws_iam_arn'                 : r'arn:aws:iam::[0-9]{12}:(?:user|role|group)/[a-zA-Z0-9\-_+=,.@/]+',
    'amazon_associate_tag'               : r'[a-z0-9]{1,20}-20',
    'azure_storage_connection_string'    : r'AccountKey=[A-Za-z0-9+/=]{88}',
    'azure_sas_token'                    : r'sv=\d{4}-\d{2}-\d{2}&s[a-z]=.*&sig=[A-Za-z0-9+/=%]+',
    'azure_cosmos_connection'            : r'AccountEndpoint=https://[^;]+;AccountKey=[A-Za-z0-9+/=]+',
    'azure_sql_connection'               : r'Server=tcp:[^;]+\.database\.windows\.net[^;]*;',
    'azure_servicebus_connection'        : r'Endpoint=sb://[^;]+\.servicebus\.windows\.net/;SharedAccessKeyName=',
    'azure_keyvault_uri'                 : r'https://[a-z0-9\-]+\.vault\.azure\.net',
    'azure_ad_token'                     : r'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    'azure_function_key'                 : r'(?:x-functions-key|code)[=:]\s*[A-Za-z0-9/+=\-_]{44,}',
    'azure_iot_hub_connection'           : r'HostName=[^;]+\.azure-devices\.net;SharedAccessKeyName=',
    'azure_redis_connection'             : r'[a-z0-9\-]+\.redis\.cache\.windows\.net:\d+,password=[A-Za-z0-9+/=]{44}',
    'github_pat_classic'                 : r'ghp_[0-9a-zA-Z]{36}',
    'github_oauth_token'                 : r'gho_[0-9a-zA-Z]{36}',
    'github_user_to_server'              : r'ghu_[0-9a-zA-Z]{36}',
    'github_server_to_server'            : r'ghs_[0-9a-zA-Z]{36}',
    'github_refresh_token'               : r'ghr_[0-9a-zA-Z]{76}',
    'github_fine_grained_pat'            : r'github_pat_[0-9a-zA-Z_]{82}',
    'github_access_token'                : r'[a-zA-Z0-9_\-]*:[a-zA-Z0-9_\-]+@github\.com',
    'gitlab_pat'                         : r'glpat-[0-9a-zA-Z\-_]{20}',
    'gitlab_runner_token'                : r'GR[0-9a-zA-Z]{20}',
    'gitlab_deploy_token'                : r'gldt-[0-9a-zA-Z\-_]{20}',
    'gitlab_group_token'                 : r'glsoat-[0-9a-zA-Z\-_]{20}',
    'bitbucket_app_password'             : r'ATBB[0-9a-zA-Z]{32}',
    'stripe_live_secret_key'             : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_live_restricted_key'         : r'rk_live_[0-9a-zA-Z]{24}',
    'stripe_test_secret_key'             : r'sk_test_[0-9a-zA-Z]{24}',
    'stripe_publishable_key_live'        : r'pk_live_[0-9a-zA-Z]{24}',
    'stripe_publishable_key_test'        : r'pk_test_[0-9a-zA-Z]{24}',
    'stripe_webhook_secret'              : r'whsec_[0-9a-zA-Z]{32}',
    'stripe_account_id'                  : r'acct_[0-9a-zA-Z]{16}',
    'stripe_customer_id'                 : r'cus_[0-9a-zA-Z]{14}',
    'paypal_braintree_access_token'      : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'paypal_braintree_sandbox'           : r'access_token\$sandbox\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret'                : r'sq0csp-[0-9A-Za-z\-_]{43}',
    'square_access_token'                : r'sqOatp-[0-9A-Za-z\-_]{22}',
    'square_access_token_v2'             : r'EAAA[a-zA-Z0-9]{60}',
    'adyen_api_key'                      : r'AQE[0-9a-zA-Z\-_]{40,}',
    'checkout_secret_key'                : r'sk_(?:live|test)_[0-9a-zA-Z]{32}',
    'razorpay_key_id'                    : r'rzp_(?:live|test)_[0-9a-zA-Z]{14}',
    'mollie_api_key'                     : r'(?:live|test)_[0-9a-zA-Z]{32}',
    'twilio_api_key'                     : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid'                 : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid'                     : r'AP[a-zA-Z0-9_\-]{32}',
    'twilio_auth_token'                  : r'(?i)twilio.*auth.*token[^0-9a-f]*([0-9a-f]{32})',
    'sendgrid_api_key'                   : r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    'mailgun_api_key'                    : r'key-[0-9a-zA-Z]{32}',
    'mailchimp_api_key'                  : r'[0-9a-f]{32}-us[0-9]{1,2}',
    'sparkpost_api_key'                  : r'[0-9a-f]{40}',
    'postmark_server_token'              : r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'nexmo_api_key'                      : r'[0-9a-f]{8}',
    'plivo_auth_id'                      : r'MA[0-9A-Z]{18}',
    'pusher_app_key'                     : r'[0-9a-f]{20}',
    'ably_api_key'                       : r'[a-zA-Z0-9_\-]{8}\.[a-zA-Z0-9_\-]{8}:[a-zA-Z0-9_\-]{43}',
    'firebase_cloud_messaging'           : r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}',
    'facebook_access_token'              : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'facebook_app_token'                 : r'EAAB[0-9A-Za-z]+',
    'instagram_graph_token'              : r'IGQV[0-9A-Za-z_\-]{170,}',
    'meta_pixel_id'                      : r'(?i)pixel.?id[^0-9]*([0-9]{15,16})',
    'twitter_bearer_token'               : r'AAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{37,}',
    'twitter_access_token'               : r'[0-9]{15,18}-[0-9a-zA-Z]{40}',
    'linkedin_access_token'              : r'AQX[0-9A-Za-z\-_]{200,}',
    'slack_bot_token'                    : r'xoxb-[0-9]{11}-[0-9]{11,13}-[0-9a-zA-Z]{24}',
    'slack_user_token'                   : r'xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[0-9a-f]{32}',
    'slack_app_token'                    : r'xapp-[0-9]-[A-Z0-9]{11}-[0-9]{13}-[0-9a-f]{64}',
    'slack_webhook_url'                  : r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    'slack_signing_secret'               : r'(?i)slack.*signing.?secret[^0-9a-f]*([0-9a-f]{32})',
    'discord_bot_token'                  : r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
    'discord_webhook_url'                : r'https://(?:canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[0-9A-Za-z_\-]+',
    'discord_nitro_code'                 : r'discord\.gift/[a-zA-Z0-9]{16,24}',
    'telegram_bot_token'                 : r'[0-9]{8,10}:[0-9A-Za-z_\-]{35}',
    'authorization_basic'                : r'(?i)basic\s+[a-zA-Z0-9=:_\+/\-]{8,}',
    'authorization_bearer'               : r'(?i)bearer\s+[a-zA-Z0-9_\-\.=:_\+/]{8,}',
    'authorization_api_key'              : r'(?i)api[_\-]?key[\s:="\'"]+[a-zA-Z0-9_\-]{16,}',
    'authorization_token'                : r'(?i)(?:auth|access)[_\-]?token[\s:="\'"]+[a-zA-Z0-9_\-\.]{16,}',
    'json_web_token'                     : r'ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_\.\+/=]*',
    'jwt_rs256'                          : r'eyJhbGciOiJSUzI1NiJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    'jwt_hs256'                          : r'eyJhbGciOiJIUzI1NiJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    'oauth2_access_token'                : r'(?i)oauth.*token[^a-zA-Z0-9]*([a-zA-Z0-9_\-\.]{32,})',
    'session_cookie'                     : r'(?i)(?:session|sess)[_\-]?(?:id|token)[^a-zA-Z0-9]*([a-zA-Z0-9_\-]{32,})',
    'csrf_token'                         : r'(?i)csrf[_\-]?token[^a-zA-Z0-9]*([a-zA-Z0-9_\-]{32,})',
    'secret_key_generic'                 : r'(?i)secret[_\-]?key[\s:="\'"]+[a-zA-Z0-9_\-!\@\#\$\%\^]{16,}',
    'rsa_private_key'                    : r'-----BEGIN RSA PRIVATE KEY-----',
    'dsa_private_key'                    : r'-----BEGIN DSA PRIVATE KEY-----',
    'ec_private_key'                     : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_key'                    : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'openssh_private_key'                : r'-----BEGIN OPENSSH PRIVATE KEY-----',
    'pkcs8_private_key'                  : r'-----BEGIN PRIVATE KEY-----',
    'ssh_public_key'                     : r'ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]{100,}',
    'mysql_connection_string'            : r'mysql://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9._\-]+(?::[0-9]+)?/[a-zA-Z0-9_\-]+',
    'postgres_connection_string'         : r'postgres(?:ql)?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9._\-]+(?::[0-9]+)?/[a-zA-Z0-9_\-]+',
    'mongodb_connection_string'          : r'mongodb(?:\+srv)?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9._\-]+(?::[0-9]+)?/[a-zA-Z0-9_\-]*',
    'redis_connection_string'            : r'redis://(?:[a-zA-Z0-9_\-]+:[^@\s]+@)?[a-zA-Z0-9._\-]+(?::[0-9]+)?',
    'mssql_connection_string'            : r'(?i)Server=[^;]+;Database=[^;]+;User\s+Id=[^;]+;Password=[^;]+',
    'elasticsearch_url'                  : r'https?://[a-zA-Z0-9._\-]+:(?:[0-9]+)?@[a-zA-Z0-9._\-]+:92[0-9]{2}',
    'influxdb_token'                     : r'(?i)influx.*token[^a-zA-Z0-9]*([a-zA-Z0-9_\-=]{86}==)',
    'neo4j_connection'                   : r'bolt://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9._\-]+:7687',
    'rabbitmq_connection'                : r'amqps?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9._\-]+(?::[0-9]+)?',
    'db_password'                        : r'(?i)db[_\-]?pass(?:word)?[\s:="\'"]+[^\s"\']{8,}',
    'database_url'                       : r'(?i)DATABASE_URL[\s:="\'"]+[a-zA-Z0-9+]+://[^\s"\']+',
    'mongo_atlas_connection'             : r'mongodb\+srv://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9._\-]+\.mongodb\.net',
    'supabase_url'                       : r'https://[a-z0-9]{20}\.supabase\.(?:co|com)',
    'supabase_service_key'               : r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+',
    'fauna_secret_key'                   : r'fn[A-Za-z0-9_\-]{40}',
    'heroku_api_key'                     : r'(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    'digitalocean_token'                 : r'(?i)(?:do|digitalocean).*token[^a-zA-Z0-9]*([a-f0-9]{64})',
    'digitalocean_spaces_key'            : r'DO[0-9A-Z]{16}',
    'cloudflare_api_key'                 : r'[0-9a-f]{37}',
    'cloudflare_api_token'               : r'[A-Za-z0-9\-_]{40}',
    'cloudflare_zone_id'                 : r'[0-9a-f]{32}',
    'vercel_token'                       : r'[A-Za-z0-9]{24}',
    'netlify_token'                      : r'[0-9a-f]{40}',
    'render_api_key'                     : r'rnd_[0-9A-Za-z]{32}',
    'fly_io_token'                       : r'fo1_[0-9A-Za-z_\-]{43}',
    'upstash_redis_token'                : r'AX[A-Za-z0-9_\-]{100,}',
    'npm_access_token'                   : r'npm_[0-9A-Za-z]{36}',
    'pypi_api_token'                     : r'pypi-[A-Za-z0-9_\-]{84,}',
    'rubygems_api_key'                   : r'rubygems_[0-9a-f]{48}',
    'circleci_token'                     : r'(?i)circle.*token[^a-zA-Z0-9]*([a-f0-9]{40})',
    'travis_ci_token'                    : r'(?i)travis.*token[^a-zA-Z0-9]*([a-zA-Z0-9_\-]{20,})',
    'jenkins_api_token'                  : r'(?i)jenkins.*token[^a-zA-Z0-9]*([0-9a-f]{34})',
    'drone_token'                        : r'(?i)drone.*token[^a-zA-Z0-9]*([a-zA-Z0-9_\-]{32,})',
    'buildkite_token'                    : r'(?i)buildkite.*token[^a-zA-Z0-9]*([a-zA-Z0-9_\-]{20,})',
    'sentry_dsn'                         : r'https://[0-9a-f]{32}@(?:o[0-9]+\.)?ingest\.sentry\.io/[0-9]+',
    'sentry_auth_token'                  : r'(?i)sentry.*token[^a-zA-Z0-9]*([a-zA-Z0-9_\-]{64})',
    'datadog_api_key'                    : r'(?i)datadog.*api.?key[^0-9a-f]*([0-9a-f]{32})',
    'datadog_app_key'                    : r'(?i)datadog.*app.?key[^0-9a-f]*([0-9a-f]{40})',
    'newrelic_api_key'                   : r'NRAK-[0-9A-Z]{27}',
    'newrelic_license_key'               : r'[0-9a-f]{40}NRAL',
    'grafana_api_key'                    : r'eyJrIjoiO[A-Za-z0-9_\-=]+',
    'dynatrace_api_token'                : r'dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}',
    'google_analytics_tracking_id'       : r'UA-[0-9]{4,10}-[0-9]{1,4}',
    'google_analytics_4_id'              : r'G-[A-Z0-9]{10}',
    'google_tag_manager_id'              : r'GTM-[A-Z0-9]{5,8}',
    'mixpanel_token'                     : r'(?i)mixpanel.*token[^a-zA-Z0-9]*([a-f0-9]{32})',
    'segment_write_key'                  : r'(?i)segment.*write.?key[^a-zA-Z0-9]*([a-zA-Z0-9]{32})',
    'hubspot_private_app_token'          : r'pat-(?:na|eu)1-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'salesforce_access_token'            : r'00D[A-Za-z0-9_!\.]{12,15}![A-Za-z0-9._]{50,}',
    'algolia_admin_key'                  : r'(?i)algolia.*admin.?key[^0-9a-f]*([0-9a-f]{32})',
    'mapbox_api_key'                     : r'pk\.eyJ1IjoiW[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    'mapbox_secret_key'                  : r'sk\.eyJ1IjoiW[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    'openai_api_key'                     : r'sk-[0-9A-Za-z]{48}',
    'openai_org_id'                      : r'org-[0-9A-Za-z]{24}',
    'anthropic_api_key'                  : r'sk-ant-api[0-9]{2}-[0-9A-Za-z_\-]{95}AA',
    'huggingface_api_key'                : r'hf_[A-Za-z0-9]{37,}',
    'replicate_api_token'                : r'r8_[A-Za-z0-9]{40}',
    'groq_api_key'                       : r'gsk_[0-9A-Za-z]{52}',
    'cloudinary_url'                     : r'cloudinary://[a-zA-Z0-9]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9]+',
    'cloudinary_api_key'                 : r'(?i)cloudinary.*api.?key[^0-9]*([0-9]{15})',
    'contentful_management_token'        : r'CFPAT-[A-Za-z0-9_\-]{43}',
    'sanity_api_token'                   : r'sk[A-Za-z0-9_\-]{50,}',
    'ghost_api_key'                      : r'[0-9a-f]{26}:[0-9a-f]{64}',
    'hashicorp_vault_token'              : r'(?:hvs|s)\.[A-Za-z0-9]{24,}',
    'doppler_service_token'              : r'dp\.st\.[a-zA-Z0-9_\-]{43}',
    'doppler_personal_token'             : r'dp\.pt\.[a-zA-Z0-9_\-]{43}',
    'aws_secrets_manager'                : r'arn:aws:secretsmanager:[a-z0-9\-]+:[0-9]{12}:secret:[a-zA-Z0-9/_+=\.@\-]+',
    'ethereum_private_key'               : r'(?i)(?:eth|ethereum).*private.?key[^0-9a-f]*([0-9a-f]{64})',
    'infura_project_id'                  : r'[0-9a-f]{32}',
    'alchemy_api_key'                    : r'[A-Za-z0-9_\-]{32}',
    'etherscan_api_key'                  : r'[A-Z0-9]{34}',
    'coinbase_api_key'                   : r'[A-Za-z0-9_\-]{16}',
    'binance_api_key'                    : r'[A-Za-z0-9]{64}',
    'web3_provider_url'                  : r'https://[a-z0-9\-]+\.infura\.io/v3/[0-9a-f]{32}',
    'docker_auth'                        : r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
    'kubernetes_service_account_token'   : r'eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    'shopify_private_app_token'          : r'shpat_[A-Za-z0-9]{32}',
    'shopify_shared_secret'              : r'shpss_[A-Za-z0-9]{32}',
    'shopify_access_token'               : r'shpca_[A-Za-z0-9]{32}',
    'shopify_partner_token'              : r'shppa_[A-Za-z0-9]{32}',
    'woocommerce_consumer_key'           : r'ck_[0-9a-f]{40}',
    'woocommerce_consumer_secret'        : r'cs_[0-9a-f]{40}',
    'notion_api_key'                     : r'secret_[A-Za-z0-9]{43}',
    'notion_integration_token'           : r'ntn_[A-Za-z0-9]{48}',
    'airtable_api_key'                   : r'key[A-Za-z0-9]{14}',
    'airtable_pat'                       : r'pat[A-Za-z0-9]{14}\.[a-f0-9]{64}',
    'asana_access_token'                 : r'[0-9]/[0-9]{16}:[0-9a-f]{32}',
    'monday_api_key'                     : r'eyJhbGciOiJIUzI1NiJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    'trello_api_key'                     : r'[0-9a-f]{32}',
    'trello_token'                       : r'[0-9a-f]{64}',
    'zoom_api_key'                       : r'(?i)zoom.*api.?key[^a-zA-Z0-9]*([A-Za-z0-9_\-]{22})',
    'typeform_access_token'              : r'tfp_[A-Za-z0-9_\-]{44}',
    'dropbox_access_token'               : r'sl\.[A-Za-z0-9\-_]{130,}',
    'okta_api_token'                     : r'00[A-Za-z0-9_\-]{40}',
    'auth0_client_secret'                : r'(?i)auth0.*(?:client.?secret|secret)[^a-zA-Z0-9]*([A-Za-z0-9_\-]{64,})',
    'linear_api_key'                     : r'lin_api_[A-Za-z0-9]{40}',
    'figma_access_token'                 : r'figd_[A-Za-z0-9_\-]{43}',
    'webflow_api_key'                    : r'(?i)webflow.*key[^a-zA-Z0-9]*([a-f0-9]{64})',
    'apify_api_token'                    : r'apify_api_[A-Za-z0-9_\-]{36}',
    'brevo_api_key'                      : r'xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}',
    'klaviyo_api_key'                    : r'pk_[0-9a-f]{34}',
    'microsoft_teams_webhook'            : r'https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9\-]+@[a-f0-9\-]+/IncomingWebhook/[a-f0-9]+/[a-f0-9\-]+',
    'zapier_webhook'                     : r'https://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+/',
    'make_webhook'                       : r'https://hook\.(?:eu1|us1|us2)?\.make\.com/[A-Za-z0-9_\-]+',
    'pipedream_webhook'                  : r'https://[a-z0-9]+\.m\.pipedream\.net',
    'env_password'                       : r'(?i)(?:PASSWORD|PASSWD|PWD|PASS)[\s]*=[\s]*(?!.*\$\{)[^\s"\']{8,}',
    'env_secret'                         : r'(?i)(?:SECRET|SECRET_KEY|SECRET_TOKEN)[\s]*=[\s]*(?!.*\$\{)[^\s"\']{8,}',
    'env_api_key'                        : r'(?i)(?:API_KEY|APIKEY|ACCESS_KEY)[\s]*=[\s]*(?!.*\$\{)[^\s"\']{8,}',
    'env_token'                          : r'(?i)(?:TOKEN|AUTH_TOKEN|ACCESS_TOKEN)[\s]*=[\s]*(?!.*\$\{)[^\s"\']{8,}',
    'env_database_url'                   : r'(?i)(?:DATABASE_URL|DB_URL|CONNECTION_STRING)[\s]*=[\s]*[a-zA-Z0-9+]+://[^\s"\']+',
    'hardcoded_password_assignment'      : r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
    'hardcoded_secret_assignment'        : r'(?i)(?:secret|secret_key|secretkey)\s*[=:]\s*["\'][^"\']{8,}["\']',
    'hardcoded_api_key_assignment'       : r'(?i)(?:api_key|apikey|api-key)\s*[=:]\s*["\'][^"\']{8,}["\']',
    'hardcoded_token_assignment'         : r'(?i)(?:token|auth_token|access_token)\s*[=:]\s*["\'][^"\']{8,}["\']',
    'inline_basic_auth'                  : r'https?://[^:\s]+:[^@\s]{4,}@[a-zA-Z0-9._\-]+',
    'json_password_field'                : r'"(?:password|passwd|pwd|secret|token|api_key|apikey|access_token)"\s*:\s*"([^"]{8,})"',
    'yaml_password_field'                : r'(?i)(?:password|secret|token|api_key):\s+[^\s{][^\n]{8,}',
    'js_variable_secret'                 : r'(?i)(?:const|let|var)\s+(?:secret|token|password|apiKey|api_key|accessToken)\s*=\s*["\'][^"\']{8,}["\']',
    'js_object_secret'                   : r'(?i)(?:secret|token|password|apiKey|api_key|accessToken)\s*:\s*["\'][^"\']{8,}["\']',
    'url_with_token_param'               : r'(?:[?&])(?:token|api_key|apikey|access_token|auth|key)=([A-Za-z0-9_\-\.]{16,})',
    'url_with_secret_param'              : r'(?:[?&])(?:secret|client_secret|app_secret)=([A-Za-z0-9_\-\.]{16,})',
    'connection_string_password'         : r'[Pp]assword=[^;]{8,}[;"]',
    'generic_secret_32'                  : r'(?i)(?:secret|token|key|password|credential)[^a-zA-Z0-9]{1,3}[A-Za-z0-9_\-+/]{32}(?![A-Za-z0-9_\-+/])',
    'generic_secret_40'                  : r'(?i)(?:secret|token|key|password|credential)[^a-zA-Z0-9]{1,3}[A-Za-z0-9_\-+/]{40}(?![A-Za-z0-9_\-+/])',
    'generic_secret_64'                  : r'(?i)(?:secret|token|key|password|credential)[^a-zA-Z0-9]{1,3}[A-Za-z0-9_\-+/]{64}(?![A-Za-z0-9_\-+/])',
    'generic_hex_40'                     : r'(?i)(?:secret|token|key|hash)[^0-9a-f]*([0-9a-f]{40})(?![0-9a-f])',
    'generic_hex_64'                     : r'(?i)(?:secret|token|key|hash)[^0-9a-f]*([0-9a-f]{64})(?![0-9a-f])',
    'signing_key'                        : r'(?i)signing.?key[^a-zA-Z0-9]*([A-Za-z0-9_\-+/=]{20,})',
    'encryption_key'                     : r'(?i)encrypt(?:ion)?.?key[^a-zA-Z0-9]*([A-Za-z0-9_\-+/=]{20,})',
    'master_key'                         : r'(?i)master.?key[^a-zA-Z0-9]*([A-Za-z0-9_\-+/=]{20,})',
    'webhook_secret'                     : r'(?i)webhook.?secret[^a-zA-Z0-9]*([A-Za-z0-9_\-]{20,})',
    'internal_ip_with_creds'             : r'https?://[a-zA-Z0-9_\-]+:[^@\s]{4,}@(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+',
    'ftp_with_creds'                     : r'ftp://[a-zA-Z0-9_\-]+:[^@\s]{4,}@[a-zA-Z0-9._\-]+',
    'vpn_preshared_key'                  : r'(?i)(?:psk|pre.?shared.?key|vpn.?key)[^a-zA-Z0-9]*([A-Za-z0-9_\-!@#$%^&*]{16,})',
    'supabase_jwt_secret'                : r'(?i)supabase.*jwt.?secret[^a-zA-Z0-9]*([A-Za-z0-9_\-+/=]{32,})',
    'planetscale_service_token'          : r'pscale_tkn_[A-Za-z0-9_\-]{43}',
    'turso_auth_token'                   : r'eyJhbGciOiJFZERTQSJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    'firebase_admin_sdk_key'             : r'(?i)firebase.*admin.*key[^a-zA-Z0-9]*([A-Za-z0-9_\-]{32,})',
    'render_api_key'                     : r'rnd_[0-9A-Za-z]{32}',
    'deno_deploy_token'                  : r'ddp_[0-9A-Za-z_\-]{24}',
    '1password_secret_key'               : r'A3-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{5}-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}',
    'apple_p8_private_key'               : r'-----BEGIN PRIVATE KEY-----',
    'firebase_web_api_key'               : r'AIza[0-9A-Za-z\-_]{35}',
    'branch_io_key'                      : r'key_(?:live|test)_[A-Za-z0-9_\-]{32}',
    'expo_access_token'                  : r'[A-Za-z0-9_\-]{32}',
}

# ─────────────────────────────────────────────
# COMPILED PATTERNS CACHE
# ─────────────────────────────────────────────
_compiled = {name: re.compile(pattern) for name, pattern in _regex.items()}

# ─────────────────────────────────────────────
# SEVERITY MAP
# ─────────────────────────────────────────────
_severity = {
    'CRITICAL': [
        'rsa_private_key','dsa_private_key','ec_private_key','pgp_private_key',
        'openssh_private_key','pkcs8_private_key','google_cloud_private_key',
        'apple_p8_private_key','ethereum_private_key','stripe_live_secret_key',
        'stripe_live_restricted_key','amazon_aws_secret_access_key',
        'amazon_aws_access_key_id','paypal_braintree_access_token',
        'twilio_auth_token','sendgrid_api_key','hashicorp_vault_token',
        'kubernetes_service_account_token','openai_api_key','anthropic_api_key',
        'doppler_service_token','mongo_atlas_connection','mysql_connection_string',
        'postgres_connection_string','mongodb_connection_string',
    ],
    'HIGH': [
        'github_pat_classic','github_fine_grained_pat','gitlab_pat',
        'slack_bot_token','discord_bot_token','telegram_bot_token',
        'facebook_access_token','twitter_bearer_token','stripe_test_secret_key',
        'mailgun_api_key','sendgrid_api_key','sentry_dsn','datadog_api_key',
        'azure_storage_connection_string','azure_cosmos_connection',
        'heroku_api_key','digitalocean_token','cloudflare_api_token',
        'shopify_private_app_token','hubspot_private_app_token',
        'salesforce_access_token','linear_api_key','notion_api_key',
    ],
}

def get_severity(name: str) -> str:
    for level, names in _severity.items():
        if name in names:
            return level
    return 'MEDIUM'


# ─────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────
class C:
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'
    WHITE  = '\033[97m'
    MAGENTA= '\033[95m'

SEV_COLOR = {'CRITICAL': C.RED, 'HIGH': C.YELLOW, 'MEDIUM': C.CYAN}

BANNER = f"""
{C.RED}{C.BOLD}
     ██╗███████╗    ███████╗███████╗ ██████╗██████╗ ███████╗████████╗
     ██║██╔════╝    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝
     ██║███████╗    ███████╗█████╗  ██║     ██████╔╝█████╗     ██║
██   ██║╚════██║    ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║
╚█████╔╝███████║    ███████║███████╗╚██████╗██║  ██║███████╗   ██║
 ╚════╝ ╚══════╝    ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝

{C.WHITE}         ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
         ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
         ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
         ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
         ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
         ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{C.RESET}

{C.DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}
{C.MAGENTA}   JavaScript Secret Scanner  |  TeamCyberOps  |  v1.0.0{C.RESET}
{C.DIM}   For authorized security testing only{C.RESET}
{C.DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}
"""


# ─────────────────────────────────────────────
# FETCHER
# ─────────────────────────────────────────────
def fetch_url(url: str, timeout: int = 15, retries: int = 2) -> Optional[str]:
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; JSSecretHunter/1.0)',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
    }
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                enc = r.headers.get_content_charset() or 'utf-8'
                return raw.decode(enc, errors='replace')
        except Exception:
            if attempt == retries - 1:
                return None
            time.sleep(1)
    return None


# ─────────────────────────────────────────────
# SCANNER
# ─────────────────────────────────────────────
def scan_content(content: str, source: str) -> list[dict]:
    findings = []
    seen = set()
    lines = content.splitlines()
    for pattern_name, compiled in _compiled.items():
        for match in compiled.finditer(content):
            value = match.group(0)
            uid = hashlib.md5(f"{pattern_name}:{value}".encode()).hexdigest()
            if uid in seen:
                continue
            seen.add(uid)
            lineno = content[:match.start()].count('\n') + 1
            line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ''
            findings.append({
                'source'   : source,
                'type'     : pattern_name,
                'severity' : get_severity(pattern_name),
                'value'    : value[:120] + ('...' if len(value) > 120 else ''),
                'line'     : lineno,
                'context'  : line_text[:200],
            })
    return findings


def extract_js_links(html: str, base_url: str) -> list[str]:
    parsed = urllib.parse.urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    links  = set()
    for m in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html, re.I):
        href = m.group(1)
        if href.startswith('http'):
            links.add(href)
        elif href.startswith('//'):
            links.add(f"{parsed.scheme}:{href}")
        elif href.startswith('/'):
            links.add(f"{base}{href}")
        else:
            path = '/'.join(parsed.path.split('/')[:-1])
            links.add(f"{base}{path}/{href}")
    for m in re.finditer(r'"([^"]+\.js(?:\?[^"]*)?)"', html):
        href = m.group(1)
        if href.startswith('http') and '.js' in href:
            links.add(href)
    return list(links)


# ─────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────
def print_finding(f: dict, quiet: bool = False):
    sev   = f['severity']
    color = SEV_COLOR.get(sev, C.WHITE)
    tag   = f"[{sev}]".ljust(10)
    print(f"  {color}{C.BOLD}{tag}{C.RESET} {C.WHITE}{f['type']}{C.RESET}")
    if not quiet:
        print(f"  {C.DIM}Line {f['line']} │ {f['context'][:100]}{C.RESET}")
        print(f"  {color}Match: {f['value'][:80]}{C.RESET}")
        print()


def save_results(findings: list[dict], outdir: Path, fmt: str, target: str):
    ts    = datetime.now().strftime('%Y%m%d_%H%M%S')
    slug  = re.sub(r'[^\w]', '_', target)[:40]
    fname = outdir / f"jssh_{slug}_{ts}.{fmt}"
    if fmt == 'json':
        fname.write_text(json.dumps(findings, indent=2), encoding='utf-8')
    elif fmt == 'csv':
        import csv, io
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=['source','type','severity','value','line','context'])
        w.writeheader()
        w.writerows(findings)
        fname.write_text(buf.getvalue(), encoding='utf-8')
    else:  # txt
        lines = []
        for f in findings:
            lines.append(f"[{f['severity']}] {f['type']}")
            lines.append(f"  Source  : {f['source']}")
            lines.append(f"  Line    : {f['line']}")
            lines.append(f"  Value   : {f['value']}")
            lines.append(f"  Context : {f['context']}")
            lines.append('')
        fname.write_text('\n'.join(lines), encoding='utf-8')
    return fname


# ─────────────────────────────────────────────
# MAIN LOGIC
# ─────────────────────────────────────────────
def scan_target(target: str, args) -> list[dict]:
    all_findings = []

    def _process_js(url: str) -> list[dict]:
        logging.info(f"Scanning: {url}")
        content = fetch_url(url, timeout=args.timeout)
        if not content:
            logging.warning(f"Failed to fetch: {url}")
            return []
        return scan_content(content, url)

    if target.startswith('http'):
        print(f"\n{C.CYAN}[*] Target   : {target}{C.RESET}")
        html = fetch_url(target, timeout=args.timeout)
        if not html:
            print(f"{C.RED}[!] Could not fetch target{C.RESET}")
            return []
        js_links = extract_js_links(html, target)
        if args.scan_page:
            js_links.append(target)
        print(f"{C.CYAN}[*] JS Files : {len(js_links)}{C.RESET}")

        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(_process_js, url): url for url in js_links}
            for i, future in enumerate(as_completed(futures), 1):
                url = futures[future]
                results = future.result()
                if results:
                    print(f"\n{C.GREEN}[+] [{i}/{len(js_links)}] {url}{C.RESET}")
                    for f in results:
                        print_finding(f, quiet=args.quiet)
                    all_findings.extend(results)
                else:
                    if args.verbose:
                        print(f"  {C.DIM}[ ] [{i}/{len(js_links)}] {url} — no secrets{C.RESET}")
    else:
        # Local file or directory
        path = Path(target)
        if path.is_file():
            files = [path]
        elif path.is_dir():
            files = list(path.rglob('*.js')) + list(path.rglob('*.min.js'))
        else:
            print(f"{C.RED}[!] Invalid target: {target}{C.RESET}")
            return []
        print(f"{C.CYAN}[*] Local Files: {len(files)}{C.RESET}")
        for f in files:
            content = f.read_text(errors='replace')
            results = scan_content(content, str(f))
            if results:
                print(f"\n{C.GREEN}[+] {f}{C.RESET}")
                for r in results:
                    print_finding(r, quiet=args.quiet)
                all_findings.extend(results)
    return all_findings


def load_targets(args) -> list[str]:
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        for line in Path(args.file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                targets.append(line)
    if args.js:
        targets.append(args.js)
    if args.local:
        targets.append(args.local)
    return targets


def main():
    parser = argparse.ArgumentParser(
        prog='jssecrethunter',
        description='JSSecretHunter — JavaScript Secret Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jssecrethunter.py -u https://example.com
  python jssecrethunter.py -u https://example.com -o json -t 20
  python jssecrethunter.py -f targets.txt -o csv --quiet
  python jssecrethunter.py -j https://cdn.example.com/app.js
  python jssecrethunter.py -l /path/to/js/files/
        """
    )
    parser.add_argument('-u',  '--url',       help='Target URL (crawl JS links from page)')
    parser.add_argument('-j',  '--js',        help='Direct JS file URL')
    parser.add_argument('-f',  '--file',      help='File with list of URLs (one per line)')
    parser.add_argument('-l',  '--local',     help='Local JS file or directory')
    parser.add_argument('-o',  '--output',    choices=['json','csv','txt'], default='json',
                                              help='Output format (default: json)')
    parser.add_argument('-d',  '--outdir',    default='output', help='Output directory (default: output/)')
    parser.add_argument('-t',  '--threads',   type=int, default=10, help='Threads (default: 10)')
    parser.add_argument('--timeout',          type=int, default=15, help='Request timeout seconds (default: 15)')
    parser.add_argument('--scan-page',        action='store_true',  help='Also scan the HTML page itself')
    parser.add_argument('--severity',         choices=['CRITICAL','HIGH','MEDIUM','ALL'], default='ALL',
                                              help='Minimum severity to show (default: ALL)')
    parser.add_argument('-q',  '--quiet',     action='store_true',  help='Suppress context lines')
    parser.add_argument('-v',  '--verbose',   action='store_true',  help='Verbose output')
    parser.add_argument('--no-banner',        action='store_true',  help='Skip banner')
    parser.add_argument('--no-save',          action='store_true',  help='Do not save output file')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format='%(levelname)s: %(message)s')

    if not args.no_banner:
        print(BANNER)

    targets = load_targets(args)
    if not targets:
        parser.print_help()
        sys.exit(1)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    start = time.time()
    all_findings: list[dict] = []

    for target in targets:
        findings = scan_target(target, args)
        # Filter severity
        if args.severity != 'ALL':
            order = ['MEDIUM','HIGH','CRITICAL']
            min_idx = order.index(args.severity)
            findings = [f for f in findings if order.index(f['severity']) >= min_idx]
        all_findings.extend(findings)

    elapsed = time.time() - start

    # Summary
    crit  = sum(1 for f in all_findings if f['severity'] == 'CRITICAL')
    high  = sum(1 for f in all_findings if f['severity'] == 'HIGH')
    med   = sum(1 for f in all_findings if f['severity'] == 'MEDIUM')

    print(f"\n{C.DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    print(f"  {C.BOLD}SCAN COMPLETE{C.RESET}  │  {elapsed:.1f}s  │  {len(all_findings)} secrets found")
    print(f"  {C.RED}CRITICAL: {crit}{C.RESET}  │  {C.YELLOW}HIGH: {high}{C.RESET}  │  {C.CYAN}MEDIUM: {med}{C.RESET}")

    if all_findings and not args.no_save:
        fname = save_results(all_findings, outdir, args.output, targets[0])
        print(f"\n  {C.GREEN}[+] Results saved → {fname}{C.RESET}")

    print(f"{C.DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}\n")


if __name__ == '__main__':
    main()
