.PHONY: help dev-db dev-backend dev-frontend migrate test lint clean

help:
	@echo "VISIONTRUST — Development Commands"
	@echo "===================================="
	@echo "make setup         - Copy .env.example to .env"
	@echo "make dev-db        - Start only the PostgreSQL container"
	@echo "make dev-backend   - Start backend in dev mode (hot reload)"
	@echo "make dev-frontend  - Start frontend dev server"
	@echo "make migrate       - Run Alembic migrations"
	@echo "make migrate-new   - Create a new migration (NAME=your_name)"
	@echo "make test          - Run pytest suite"
	@echo "make docker-up     - Start full stack with Docker Compose"
	@echo "make docker-down   - Stop all containers"
	@echo "make clean         - Remove __pycache__ and .pyc files"

setup:
	@if not exist .env copy .env.example .env && echo "Created .env — edit it with real secrets."

dev-db:
	docker compose up db -d

dev-backend:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend:
	cd frontend && npm run dev

migrate:
	cd backend && alembic upgrade head

migrate-new:
	cd backend && alembic revision --autogenerate -m "$(NAME)"

test:
	cd backend && pytest tests/ -v --tb=short

lint:
	cd backend && ruff check app/ tests/

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
