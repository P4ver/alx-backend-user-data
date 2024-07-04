#!/usr/bin/env python3
"""A module for filtering logs.
"""
import os
import re
import logging
import mysql.connector
from typing import List


patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str,
        ) -> str:
    """Filters a log line.
    """
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """Creates a new logger for user data.
    """
    lg = logging.getLogger("user_data")
    sh = logging.StreamHandler()
    sh.setFormatter(RedactingFormatter(PII_FIELDS))
    lg.setLevel(logging.INFO)
    lg.propagate = False
    lg.addHandler(sh)
    return lg


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Creates a connector to a database,"""
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    conn = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return conn


def main():
    """Logs the information about user records in a table.
    """
    flds = "name,email,phone,ssn,password,ip,last_login,user_agent"
    cols = flds.split(',')
    qry = "SELECT {} FROM users;".format(flds)
    info_lg = get_logger()
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(qry)
        rows = cur.fetchall()
        for row in rows:
            rec = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(cols, row),
            )
            msg = '{};'.format('; '.join(list(rec)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_rec = logging.LogRecord(*args)
            info_lg.handle(log_rec)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """formats a LogRecord.
        """
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt


if __name__ == "__main__":
    main()
