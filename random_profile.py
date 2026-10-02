"""Random profile generator: password, full name, age."""
from __future__ import annotations

import random
import secrets
import string


# First names + last names — pool đủ rộng, common names US/EU
_FIRST_NAMES = (
    "Aaron", "Adam", "Alex", "Alexander", "Andrew", "Anthony", "Asher", "Austin",
    "Benjamin", "Blake", "Brandon", "Brian", "Caleb", "Cameron", "Carter", "Charles",
    "Christian", "Christopher", "Cody", "Cole", "Colton", "Connor", "Daniel", "David",
    "Dean", "Dominic", "Dylan", "Easton", "Edward", "Elijah", "Eric", "Ethan",
    "Evan", "Felix", "Gabriel", "Gavin", "George", "Grayson", "Henry", "Hudson",
    "Hunter", "Ian", "Isaac", "Isaiah", "Jack", "Jackson", "Jacob", "James",
    "Jason", "Jeremy", "Joel", "John", "Jonathan", "Jordan", "Joseph", "Joshua",
    "Julian", "Justin", "Kevin", "Kyle", "Landon", "Leo", "Levi", "Liam",
    "Logan", "Lucas", "Luke", "Mark", "Matthew", "Max", "Mason", "Michael",
    "Miles", "Nathan", "Nicholas", "Noah", "Oliver", "Owen", "Parker", "Patrick",
    "Paul", "Peter", "Philip", "Quinn", "Reid", "Robert", "Ryan", "Samuel",
    "Sean", "Sebastian", "Simon", "Steven", "Thomas", "Timothy", "Tyler", "Vincent",
    "Wesley", "William", "Wyatt", "Xavier", "Zachary", "Zane",
    "Ava", "Amelia", "Aria", "Aurora", "Avery", "Bella", "Brooklyn", "Camila",
    "Charlotte", "Chloe", "Claire", "Eleanor", "Elena", "Eliana", "Elizabeth",
    "Ella", "Ellie", "Emily", "Emma", "Evelyn", "Gianna", "Grace", "Hannah",
    "Harper", "Hazel", "Isabella", "Isla", "Ivy", "Julia", "Kennedy", "Layla",
    "Leah", "Lila", "Lily", "Lucy", "Luna", "Madison", "Mia", "Mila",
    "Naomi", "Natalie", "Nora", "Olivia", "Penelope", "Riley", "Ruby", "Sadie",
    "Sarah", "Savannah", "Scarlett", "Sofia", "Sophia", "Stella", "Valentina",
    "Victoria", "Violet", "Willow", "Zoe",
)

_LAST_NAMES = (
    "Adams", "Allen", "Anderson", "Bailey", "Baker", "Barnes", "Bell", "Bennett",
    "Brooks", "Brown", "Bryant", "Butler", "Campbell", "Carter", "Clark", "Coleman",
    "Collins", "Cook", "Cooper", "Cox", "Davis", "Diaz", "Edwards", "Evans",
    "Fisher", "Flores", "Foster", "Garcia", "Gomez", "Gonzalez", "Gray", "Green",
    "Griffin", "Hall", "Harris", "Hayes", "Henderson", "Hernandez", "Hill", "Howard",
    "Hughes", "Jackson", "James", "Jenkins", "Johnson", "Jones", "Kelly", "King",
    "Lee", "Lewis", "Long", "Lopez", "Martin", "Martinez", "Miller", "Mitchell",
    "Moore", "Morgan", "Morris", "Murphy", "Nelson", "Nguyen", "Parker", "Perez",
    "Perry", "Peterson", "Phillips", "Powell", "Price", "Ramirez", "Reed", "Reyes",
    "Richardson", "Rivera", "Roberts", "Robinson", "Rodriguez", "Rogers", "Ross",
    "Russell", "Sanchez", "Sanders", "Scott", "Simmons", "Smith", "Stewart", "Sullivan",
    "Taylor", "Thomas", "Thompson", "Torres", "Turner", "Walker", "Ward", "Watson",
    "White", "Williams", "Wilson", "Wood", "Wright", "Young",
)


def random_full_name() -> str:
    """Random first + last name (Title Case)."""
    return f"{secrets.choice(_FIRST_NAMES)} {secrets.choice(_LAST_NAMES)}"


def random_age(*, low: int = 19, high: int = 30) -> int:
    """Random age trong khoảng [low, high]."""
    return secrets.randbelow(high - low + 1) + low


def random_password(*, length: int = 12) -> str:
    """Random password 12 ký tự:
        - Bắt đầu bằng 1 chữ HOA.
        - Có chữ thường + số.
        - Kết thúc bằng @ hoặc # (ký tự ngẫu nhiên trong "@#").

    Format: [A-Z][a-z0-9]*8 + 1 chữ + 1 số + [@#]
    Tổng 12 ký tự.
    """
    if length < 4:
        raise ValueError("password length tối thiểu là 4")

    upper = secrets.choice(string.ascii_uppercase)
    end = secrets.choice("@#")

    # Phần giữa (length - 2) ký tự — đảm bảo có ít nhất 1 lower + 1 digit
    middle_len = length - 2
    if middle_len < 2:
        middle = secrets.choice(string.ascii_lowercase) + secrets.choice(string.digits)
    else:
        # Lấy 1 lower + 1 digit + (middle_len - 2) ký tự random từ alphanumeric
        chars = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
        ]
        pool = string.ascii_lowercase + string.digits
        chars.extend(secrets.choice(pool) for _ in range(middle_len - 2))
        # Shuffle phần middle để vị trí lower/digit không cố định
        random.shuffle(chars)
        middle = "".join(chars)

    return f"{upper}{middle}{end}"


def random_profile() -> dict:
    """Combo random: name + age + password + birthdate (compute từ age)."""
    from datetime import datetime
    age = random_age()
    name = random_full_name()
    password = random_password()
    today = datetime.utcnow()
    # Chọn ngày random trước, rồi tính năm sinh sao cho tuổi đọc lại luôn đúng.
    # Công thức cũ luôn dùng ``today.year - age`` nên birthday chưa tới sẽ bị
    # hụt 1 tuổi (random_age=19 nhưng session ghi age=18).
    month = secrets.randbelow(12) + 1
    day = secrets.randbelow(28) + 1
    birthday_passed = (month, day) <= (today.month, today.day)
    birth_year = today.year - age if birthday_passed else today.year - age - 1
    return {
        "name": name,
        "age": age,
        "password": password,
        "birthdate": f"{birth_year:04d}-{month:02d}-{day:02d}",
    }


# ─────────────────────────────────────────────────────────────────────
# India profile / billing generator
# ─────────────────────────────────────────────────────────────────────

# Tên Ấn Độ phổ biến (mix nam/nữ) — dùng cho profile + billing name.
_IN_FIRST_NAMES = (
    "Aarav", "Aditya", "Arjun", "Ayaan", "Dhruv", "Ishaan", "Kabir", "Karan",
    "Krishna", "Reyansh", "Rohan", "Rudra", "Sai", "Shaurya", "Vihaan", "Vivaan",
    "Aanya", "Aadhya", "Ananya", "Anika", "Diya", "Ira", "Kavya", "Myra",
    "Navya", "Neha", "Pari", "Pooja", "Priya", "Riya", "Saanvi", "Tara",
)

_IN_LAST_NAMES = (
    "Sharma", "Verma", "Gupta", "Singh", "Kumar", "Patel", "Reddy", "Nair",
    "Iyer", "Rao", "Das", "Bose", "Chopra", "Mehta", "Jain", "Shah",
    "Agarwal", "Pillai", "Menon", "Banerjee", "Chatterjee", "Mukherjee",
    "Desai", "Kapoor", "Malhotra", "Joshi", "Saxena", "Bhat", "Nayak", "Sinha",
)

# (city, state, pincode_prefix) — pincode India = 6 chữ số, prefix theo vùng.
_IN_CITIES = (
    ("Mumbai", "Maharashtra", "4000"),
    ("Delhi", "Delhi", "1100"),
    ("Bengaluru", "Karnataka", "5600"),
    ("Chennai", "Tamil Nadu", "6000"),
    ("Hyderabad", "Telangana", "5000"),
    ("Kolkata", "West Bengal", "7000"),
    ("Pune", "Maharashtra", "4110"),
    ("Ahmedabad", "Gujarat", "3800"),
    ("Jaipur", "Rajasthan", "3020"),
    ("Lucknow", "Uttar Pradesh", "2260"),
)

_IN_STREETS = (
    "MG Road", "Brigade Road", "Linking Road", "Park Street", "Anna Salai",
    "Connaught Place", "Banjara Hills", "Koramangala", "Andheri West",
    "Salt Lake", "Jubilee Hills", "Indiranagar", "Sector 18", "Civil Lines",
)


def random_india_phone() -> str:
    """Số di động Ấn Độ hợp lệ: +91 + 10 chữ số, bắt đầu 6-9."""
    first = secrets.choice("6789")
    rest = "".join(secrets.choice(string.digits) for _ in range(9))
    return f"+91{first}{rest}"


def random_india_profile() -> dict:
    """Profile + billing Ấn Độ đầy đủ để điền form (name, phone, address...).

    Trả về superset của ``random_profile()`` + các field địa chỉ India:
    name, first_name, last_name, age, password, birthdate, phone,
    address_line1, city, state, postal_code, country, country_code.
    """
    from datetime import datetime

    first = secrets.choice(_IN_FIRST_NAMES)
    last = secrets.choice(_IN_LAST_NAMES)
    age = random_age()
    today = datetime.utcnow()
    birth_year = today.year - age
    month = secrets.randbelow(12) + 1
    day = secrets.randbelow(28) + 1

    city, state, pin_prefix = secrets.choice(_IN_CITIES)
    house_no = secrets.randbelow(999) + 1
    street = secrets.choice(_IN_STREETS)
    postal_code = f"{pin_prefix}{secrets.randbelow(100):02d}"

    return {
        "name": f"{first} {last}",
        "first_name": first,
        "last_name": last,
        "age": age,
        "password": random_password(),
        "birthdate": f"{birth_year:04d}-{month:02d}-{day:02d}",
        "phone": random_india_phone(),
        "address_line1": f"{house_no}, {street}",
        "city": city,
        "state": state,
        "postal_code": postal_code,
        "country": "India",
        "country_code": "IN",
    }
