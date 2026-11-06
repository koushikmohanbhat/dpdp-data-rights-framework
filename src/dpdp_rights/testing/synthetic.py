"""Synthetic Indian personal data for tests and sandboxes. Never use real people's data in tests.

Values are valid in form (Aadhaar passes the Verhoeff check, PAN follows the format, mobile numbers start
with 6-9) so detectors find them, but they are generated, and emails use the reserved ``example.com``.
Deterministic for a given seed.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from ..pii.detectors import verhoeff_check_digit

FIRST = ["Aarav", "Priya", "Rahul", "Ananya", "Vikram", "Meera", "Arjun", "Kavya", "Rohan", "Isha",
         "Siddharth", "Lakshmi", "Farhan", "Neha", "Karthik", "Pooja", "Imran", "Divya", "Manish", "Sneha"]
LAST = ["Sharma", "Iyer", "Reddy", "Nair", "Patel", "Gupta", "Khan", "Menon", "Rao", "Banerjee",
        "Singh", "Kulkarni", "Das", "Pillai", "Joshi", "Chatterjee", "Verma", "Hegde", "Shetty", "Bhat"]
PLACES = [("MG Road", "Bengaluru", "560001"), ("Linking Road", "Mumbai", "400050"),
          ("Anna Salai", "Chennai", "600002"), ("Park Street", "Kolkata", "700016"),
          ("Banjara Hills", "Hyderabad", "500034"), ("FC Road", "Pune", "411004"),
          ("Connaught Place", "New Delhi", "110001"), ("MI Road", "Jaipur", "302001")]


@dataclass(frozen=True)
class SyntheticPerson:
    external_id: str
    name: str
    email: str
    phone: str
    aadhaar: str
    pan: str
    upi: str
    address: str

    def message(self) -> str:
        """A realistic first message to an onboarding agent."""
        return (f"My name is {self.name}. Aadhaar {self.aadhaar}, PAN {self.pan}. "
                f"Reach me on {self.phone} or {self.email}. Address: {self.address}.")


def people(n: int = 3, seed: int = 7) -> list[SyntheticPerson]:
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        first, last = rnd.choice(FIRST), rnd.choice(LAST)
        base = str(rnd.randint(2, 9)) + "".join(str(rnd.randint(0, 9)) for _ in range(10))
        a = base + verhoeff_check_digit(base)
        pan = ("".join(rnd.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(3)) + "P" + last[0].upper()
               + f"{rnd.randint(1000, 9999)}" + rnd.choice("ABCDEFGHJKLMNPQRSTUVWXYZ"))
        mobile = str(rnd.randint(6, 9)) + "".join(str(rnd.randint(0, 9)) for _ in range(9))
        street, city, pin = rnd.choice(PLACES)
        out.append(SyntheticPerson(
            external_id=f"synthetic-{seed}-{i}",
            name=f"{first} {last}",
            email=f"{first.lower()}.{last.lower()}{i}@example.com",
            phone=f"+91 {mobile[:5]} {mobile[5:]}",
            aadhaar=f"{a[:4]} {a[4:8]} {a[8:]}",
            pan=pan,
            upi=f"{first.lower()}{i}@okaxis",
            address=f"{rnd.randint(1, 99)}, {street}, {city} {pin}",
        ))
    return out
