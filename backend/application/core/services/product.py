from application.core.models import Product
from application.core.queries.branch import get_branches_by_product


def set_repository_default_branch(product: Product) -> None:
    current_repository_default_branch = product.repository_default_branch
    new_repository_default_branch = product.repository_default_branch
    branches = get_branches_by_product(product)
    if not branches:
        new_repository_default_branch = None
    else:
        if len(branches) == 1:
            new_repository_default_branch = branches[0]
        else:
            # find branches matching 0.0.0-dev and sort them alphabetically descending, then pick the first one
            sorted_branches = sorted(
                filter(lambda branch: branch.name.endswith("0.0.0-dev"), branches),
                key=lambda branch: branch.name,
                reverse=True
            )

            if sorted_branches:
                new_repository_default_branch = sorted_branches[0]

    if new_repository_default_branch != current_repository_default_branch:
        product.repository_default_branch = new_repository_default_branch
        product.save()
