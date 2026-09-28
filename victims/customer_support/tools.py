from victims.customer_support.fixtures import REVIEWS

def search_reviews(product_id: str) -> str | None:
    return REVIEWS.get(product_id)
