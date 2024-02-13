import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "chess.settings")
app = Celery("chess")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

CELERY_BROKER_URL = "amqp://root:Qwerty_123@localhost:5672"
CELERY_RESULT_BACKEND = "redis://localhost:6379"