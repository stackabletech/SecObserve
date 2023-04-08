from typing import Optional

from application.core.models import Parser


def get_parser_by_id(id: int) -> Optional[Parser]:
    try:
        return Parser.objects.get(id=id)
    except Parser.DoesNotExist:
        return None


def get_parser_by_name(name: str) -> Optional[Parser]:
    try:
        return Parser.objects.get(name=name)
    except Parser.DoesNotExist:
        return None
