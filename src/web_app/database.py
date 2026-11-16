"""Conexión a PostgreSQL. Las credenciales vienen solo de variables de entorno."""

import psycopg
from psycopg.rows import dict_row

from web_app import config


def get_connection() -> psycopg.Connection:
    return psycopg.connect(**config.db_conninfo(), row_factory=dict_row)
