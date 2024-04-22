import logging

from constance import config
from huey import crontab
from huey.contrib.djhuey import db_periodic_task, lock_task

from application.commons.services.tasks import handle_task_exception
from application.core.services.exploits import import_github_poc, import_vulncheck_kev
from application.core.services.housekeeping import delete_inactive_branches

logger = logging.getLogger("secobserve.core")


@db_periodic_task(
    crontab(
        minute=config.BRANCH_HOUSEKEEPING_CRONTAB_MINUTES,
        hour=config.BRANCH_HOUSEKEEPING_CRONTAB_HOURS,
    )
)
@lock_task("branch_housekeeping")
def task_branch_housekeeping() -> None:
    logger.info("--- Branch_housekeeping - start ---")

    try:
        delete_inactive_branches()
    except Exception as e:
        handle_task_exception(e)

    logger.info("--- Branch_housekeeping - finished ---")


@db_periodic_task(
    crontab(
        minute=config.BACKGROUND_EXPLOITS_IMPORT_CRONTAB_MINUTES,
        hour=config.BACKGROUND_EXPLOITS_IMPORT_CRONTAB_HOURS,
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
