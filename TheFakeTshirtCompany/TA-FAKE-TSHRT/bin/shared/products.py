#!/usr/bin/env python3
"""
Products Configuration - The FAKE T-Shirt Company
Product catalog with IT-themed apparel for web access logs.
Includes t-shirts, hoodies, joggers, and accessories.
"""

import random
from typing import Optional, Tuple, List
from dataclasses import dataclass


@dataclass
class Product:
    """A product in the catalog."""
    id: int
    slug: str
    name: str
    price: int
    category: str
    product_type: str = "tshirt"  # tshirt, hoodie, joggers, accessory


# =============================================================================
# PRODUCT CATALOG
# =============================================================================
# Prices in USD - T-shirts $35-45, Hoodies $70-85, Joggers $65-75, Accessories $25-40

PRODUCTS: List[Product] = [
    # =========================================================================
    # T-SHIRTS ($35-45)
    # =========================================================================
    # Developer humor
    Product(1, "works-on-my-machine-tee", "It Works On My Machine Tee", 40, "developer", "tshirt"),
    Product(2, "sudo-sandwich-tee", "sudo make me a sandwich Tee", 38, "developer", "tshirt"),
    Product(3, "no-place-like-localhost-tee", "There's No Place Like 127.0.0.1 Tee", 40, "developer", "tshirt"),
    Product(4, "test-in-production-tee", "I Test In Production Tee", 45, "developer", "tshirt"),
    Product(5, "select-from-users-tee", "SELECT * FROM users Tee", 43, "developer", "tshirt"),
    Product(6, "git-happens-tee", "Git Happens Tee", 35, "developer", "tshirt"),
    Product(7, "i-am-root-tee", "I Am Root Tee", 38, "developer", "tshirt"),
    Product(8, "hello-world-tee", "Hello World Tee", 34, "developer", "tshirt"),
    Product(9, "semicolon-tee", "Semicolon Saved My Life Tee", 37, "developer", "tshirt"),
    Product(10, "99-bugs-tee", "99 Little Bugs Tee", 40, "developer", "tshirt"),

    # Sysadmin/DevOps
    Product(11, "have-you-tried-tee", "Have You Tried Rebooting Tee", 40, "sysadmin", "tshirt"),
    Product(12, "chmod-777-tee", "chmod 777 Tee", 38, "sysadmin", "tshirt"),
    Product(13, "it-crowd-tee", "I'm A Sysadmin Tee", 42, "sysadmin", "tshirt"),
    Product(14, "coffee-sql-tee", "Coffee Into SQL Tee", 39, "sysadmin", "tshirt"),
    Product(15, "its-always-dns-tee", "It's Always DNS Tee", 37, "sysadmin", "tshirt"),
    Product(16, "uptime-365-tee", "Uptime 365 Days Tee", 45, "sysadmin", "tshirt"),
    Product(17, "no-backup-tee", "No Backup No Sympathy Tee", 38, "sysadmin", "tshirt"),
    Product(18, "yaml-spaces-tee", "YAML Spaces Matter Tee", 36, "sysadmin", "tshirt"),
    Product(19, "kubernetes-tee", "Kubernetes Captain Tee", 43, "sysadmin", "tshirt"),
    Product(20, "docker-whale-tee", "I Speak Whale Tee", 40, "sysadmin", "tshirt"),

    # Security
    Product(21, "trust-no-one-tee", "Trust No One Tee", 42, "security", "tshirt"),
    Product(22, "password-123456-tee", "Password 123456 Tee", 38, "security", "tshirt"),
    Product(23, "social-engineer-tee", "Social Engineer Tee", 40, "security", "tshirt"),
    Product(24, "hack-the-planet-tee", "Hack The Planet Tee", 45, "security", "tshirt"),
    Product(25, "zero-day-tee", "Zero Day Tee", 43, "security", "tshirt"),

    # Classic nerd
    Product(26, "binary-people-tee", "10 Types Of People Tee", 40, "nerd", "tshirt"),
    Product(27, "keep-calm-code-tee", "Keep Calm Code On Tee", 35, "nerd", "tshirt"),
    Product(28, "eat-sleep-code-tee", "Eat Sleep Code Repeat Tee", 37, "nerd", "tshirt"),
    Product(29, "code-ninja-tee", "Code Ninja Tee", 38, "nerd", "tshirt"),
    Product(30, "stack-overflow-tee", "Copy From Stack Overflow Tee", 38, "nerd", "tshirt"),

    # Modern tech
    Product(31, "ai-overlords-tee", "AI Overlords Tee", 42, "modern", "tshirt"),
    Product(32, "chatgpt-homework-tee", "ChatGPT Did My Homework Tee", 40, "modern", "tshirt"),
    Product(33, "cloud-native-tee", "Born In The Cloud Tee", 39, "modern", "tshirt"),
    Product(34, "serverless-tee", "Serverless Tee", 43, "modern", "tshirt"),
    Product(35, "remote-worker-tee", "Work From Home Tee", 38, "modern", "tshirt"),

    # =========================================================================
    # HOODIES ($70-85)
    # =========================================================================
    Product(36, "works-on-my-machine-hoodie", "It Works On My Machine Hoodie", 79, "developer", "hoodie"),
    Product(37, "sudo-sandwich-hoodie", "sudo make me a sandwich Hoodie", 75, "developer", "hoodie"),
    Product(38, "git-happens-hoodie", "Git Happens Hoodie", 72, "developer", "hoodie"),
    Product(39, "i-am-root-hoodie", "I Am Root Hoodie", 75, "developer", "hoodie"),
    Product(40, "99-bugs-hoodie", "99 Little Bugs Hoodie", 79, "developer", "hoodie"),
    Product(41, "have-you-tried-hoodie", "Have You Tried Rebooting Hoodie", 79, "sysadmin", "hoodie"),
    Product(42, "its-always-dns-hoodie", "It's Always DNS Hoodie", 75, "sysadmin", "hoodie"),
    Product(43, "kubernetes-hoodie", "Kubernetes Captain Hoodie", 85, "sysadmin", "hoodie"),
    Product(44, "docker-whale-hoodie", "I Speak Whale Hoodie", 79, "sysadmin", "hoodie"),
    Product(45, "hack-the-planet-hoodie", "Hack The Planet Hoodie", 85, "security", "hoodie"),
    Product(46, "zero-day-hoodie", "Zero Day Hoodie", 82, "security", "hoodie"),
    Product(47, "trust-no-one-hoodie", "Trust No One Hoodie", 79, "security", "hoodie"),
    Product(48, "binary-people-hoodie", "10 Types Of People Hoodie", 75, "nerd", "hoodie"),
    Product(49, "code-ninja-hoodie", "Code Ninja Hoodie", 75, "nerd", "hoodie"),
    Product(50, "ai-overlords-hoodie", "AI Overlords Hoodie", 82, "modern", "hoodie"),
    Product(51, "cloud-native-hoodie", "Born In The Cloud Hoodie", 79, "modern", "hoodie"),
    Product(52, "serverless-hoodie", "Serverless Hoodie", 82, "modern", "hoodie"),

    # =========================================================================
    # JOGGERS ($65-75)
    # =========================================================================
    Product(53, "developer-joggers", "Developer Mode Joggers", 69, "developer", "joggers"),
    Product(54, "code-all-day-joggers", "Code All Day Joggers", 65, "developer", "joggers"),
    Product(55, "sysadmin-joggers", "Sysadmin On Call Joggers", 69, "sysadmin", "joggers"),
    Product(56, "devops-joggers", "DevOps Life Joggers", 72, "sysadmin", "joggers"),
    Product(57, "security-joggers", "Security Team Joggers", 69, "security", "joggers"),
    Product(58, "hacker-joggers", "Ethical Hacker Joggers", 72, "security", "joggers"),
    Product(59, "nerd-joggers", "Nerd Mode Joggers", 65, "nerd", "joggers"),
    Product(60, "tech-joggers", "Tech Life Joggers", 69, "modern", "joggers"),
    Product(61, "remote-joggers", "Remote Worker Joggers", 65, "modern", "joggers"),
    Product(62, "startup-joggers", "Startup Life Joggers", 72, "modern", "joggers"),

    # =========================================================================
    # ACCESSORIES ($25-40) - Caps, Beanies, Bags
    # =========================================================================
    Product(63, "developer-cap", "Developer Cap", 32, "developer", "accessory"),
    Product(64, "git-beanie", "Git Beanie", 28, "developer", "accessory"),
    Product(65, "code-tote", "Code Tote Bag", 35, "developer", "accessory"),
    Product(66, "sysadmin-cap", "Sysadmin Cap", 32, "sysadmin", "accessory"),
    Product(67, "devops-beanie", "DevOps Beanie", 28, "sysadmin", "accessory"),
    Product(68, "security-cap", "Security Team Cap", 32, "security", "accessory"),
    Product(69, "hacker-beanie", "Hacker Beanie", 30, "security", "accessory"),
    Product(70, "nerd-cap", "Nerd Cap", 28, "nerd", "accessory"),
    Product(71, "tech-backpack", "Tech Backpack", 85, "modern", "accessory"),
    Product(72, "laptop-sleeve", "Developer Laptop Sleeve", 40, "modern", "accessory"),
]

PRODUCT_CATEGORIES = ["developer", "sysadmin", "security", "nerd", "modern"]
PRODUCT_TYPES = ["tshirt", "hoodie", "joggers", "accessory"]
PRODUCT_CURRENCY = "USD"


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_product_count() -> int:
    """Get product count."""
    return len(PRODUCTS)


def get_random_product() -> Product:
    """Get random product."""
    return random.choice(PRODUCTS)


def get_product_by_id(product_id: int) -> Optional[Product]:
    """Get product by ID."""
    for product in PRODUCTS:
        if product.id == product_id:
            return product
    return None


def get_random_product_url() -> str:
    """
    Get random product URL path.
    Returns: /products/works-on-my-machine or /products/category/developer
    """
    product = get_random_product()

    # 70% direct product, 30% category browse
    if random.random() < 0.7:
        return f"/products/{product.slug}"
    else:
        return f"/products/category/{product.category}"


def get_random_cart_item() -> Tuple[str, int]:
    """
    Get random product for cart/checkout.
    Returns: (slug, price)
    """
    product = get_random_product()
    return (product.slug, product.price)


# =============================================================================
# URL PATTERNS FOR WEB ACCESS LOGS
# =============================================================================

STATIC_PAGES = [
    "/",
    "/about",
    "/contact",
    "/shipping",
    "/returns",
    "/faq",
    "/privacy",
    "/terms",
]

API_ENDPOINTS = [
    "/api/v1/products",
    "/api/v1/cart",
    "/api/v1/user/profile",
    "/api/v1/search",
    "/api/v1/recommendations",
]


def get_random_static_page() -> str:
    """Get random static page."""
    return random.choice(STATIC_PAGES)


def get_random_api_endpoint() -> str:
    """Get random API endpoint."""
    return random.choice(API_ENDPOINTS)


def get_random_url() -> str:
    """
    Get random URL based on typical user behavior.
    Distribution: 40% products, 30% static, 20% API, 10% cart/checkout
    """
    roll = random.randint(0, 99)

    if roll < 40:
        return get_random_product_url()
    elif roll < 70:
        return get_random_static_page()
    elif roll < 90:
        return get_random_api_endpoint()
    else:
        # Cart/checkout flow
        step = random.randint(0, 2)
        if step == 0:
            return "/cart"
        elif step == 1:
            return "/checkout"
        else:
            return "/checkout/complete"


# =============================================================================
# EMAIL SUBJECTS (for Exchange logs)
# =============================================================================

EMAIL_SUBJECTS_INTERNAL = [
    "Q4 Budget Review",
    "Team Meeting Notes",
    "Project Update",
    "Weekly Status Report",
    "Action Items from Today",
    "FW: Customer Feedback",
    "RE: Database Migration Plan",
    "Vacation Request",
    "IT Security Training Reminder",
    "New Employee Onboarding",
    "RE: Invoice #12345",
    "Contract Review Required",
    "Monthly Sales Report",
    "Infrastructure Upgrade Plan",
    "RE: Access Request",
]


def get_random_email_subject() -> str:
    """Get random internal email subject."""
    return random.choice(EMAIL_SUBJECTS_INTERNAL)


if __name__ == "__main__":
    print("Product Catalog - The FAKE T-Shirt Company")
    print("=" * 50)
    print(f"Total products: {get_product_count()}")
    print(f"Categories: {', '.join(PRODUCT_CATEGORIES)}")
    print()

    # Sample products
    print("Sample products:")
    for _ in range(5):
        p = get_random_product()
        print(f"  [{p.id}] {p.name} - ${p.price} ({p.category})")

    print()
    print("Sample URLs:")
    for _ in range(5):
        print(f"  {get_random_url()}")
