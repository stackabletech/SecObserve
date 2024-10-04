import logging

from huey import crontab
from huey.contrib.djhuey import db_periodic_task, lock_task

from application.commons import settings_static
from application.commons.services.tasks import handle_task_exception
from application.core.services.exploits import import_github_poc, import_vulncheck_kev
from application.core.services.housekeeping import (
    delete_inactive_branches_and_set_flags,
)
from application.core.services.risk_acceptance_expiry_task import (
    expire_risk_acceptances,
)

logger = logging.getLogger("secobserve.core")


@db_periodic_task(
    crontab(
        minute=settings_static.branch_housekeeping_crontab_minute,
        hour=settings_static.branch_housekeeping_crontab_hour,
    )
)
@lock_task("branch_housekeeping")
def task_branch_housekeeping() -> None:
    logger.info("--- Branch_housekeeping - start ---")

    try:
        delete_inactive_branches_and_set_flags()
    except Exception as e:
        handle_task_exception(e)

    logger.info("--- Branch_housekeeping - finished ---")


@db_periodic_task(
    crontab(
        minute=settings_static.background_exploits_import_crontab_minutes,
        hour=settings_static.background_exploits_import_crontab_hours,
    )
)
@lock_task("import_exploits")
def task_import_exploits() -> None:
    logger.info("--- Import_Exploits - start ---")

    try:
        import_vulncheck_kev()
        import_github_poc()
    except Exception as e:
        handle_task_exception(e)

    logger.info("--- Import_Exploits - finished ---")


@db_periodic_task(
    crontab(
        minute=settings_static.risk_acceptance_expiry_crontab_minute,
        hour=settings_static.risk_acceptance_expiry_crontab_hour,
    )
)
@lock_task("risk_acceptance_expiry")
def task_risk_acceptance_expiry() -> None:
    logger.info("--- Expire risk acceptances - start ---")

    try:
        expire_risk_acceptances()
    except Exception as e:
        handle_task_exception(e)

    logger.info("--- Expire risk acceptances - finished ---")
