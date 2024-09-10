# Netdis
## Web based binary analysis

 ![Netdis user interface](netdis.png)

 ## Deployment configuration

 The address of the backend needs to be specified in the respective `frontend/.env.vite.dev` and `frontend/.env.vite.prod` files, depending on the type of deployment. For development, this can typically be left at `http://localhost:8000/`. When deploying to production, this must point to the address of the backend. Additionally, the Vite files are built using this environment variable, so it may not reflect until the build has completed and the built files are available in the `frontend/dist/` directory.

 The remaining environment variables are defined in the `.env.dev` and `.env.prod` files. When deploying to production, the `DJANGO_ALLOWED_HOSTS` and `CORS_ALLOWED_ORIGINS` must contain the address of the frontend, which is typically just the host, as it is being served via nginx on port 80.

### Deployment commands

 Deploy for development:

 `docker-compose -f docker-compose.yml -f docker-compose-dev.yml up --build`

 Deploy for production:

 `docker-compose -f docker-compose.yml -f docker-compose-prod.yml up --build`

 ### Databse Migrations

 Between changes to any Django models, old PostgreSQL volumes will need to be deleted. Otherwise, there will be errors to non-existant fields.

 `docker volume rm netdis_postgres_data`