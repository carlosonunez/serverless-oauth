# serverless-oauth

Authenticate into an OAuth service entirely through AWS Lambda.

## How to deploy

1. Run `scripts/setup` and answer the questions.
1. Create a `.env` from `.env.example` and fill it out.
2. Source common bash aliases: `source bash_aliases`
3. Run unit tests: `unit`
4. Run integration tests (uses AWS; should be free): `integration`
5. Deploy to your AWS account: `ENVIRONMENT=production deploy`
