"""03 PhoneIntel: offline phone-number parsing with the phonenumbers library. Local only."""

from __future__ import annotations

from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec
from core.validation import TargetType

NAME = "PhoneIntel"


def run(ctx) -> list[Finding]:
    # Imported here: its carrier and region tables hold about 150 MB that most sessions never need.
    import phonenumbers
    from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

    types = {value: name.replace("_", " ").lower() for name, value in vars(PhoneNumberType).items()
             if name.isupper() and isinstance(value, int)}
    number = phonenumbers.parse(ctx.target, None)
    ctx.emit(f"[i] parsing {ctx.target} offline (phonenumbers {phonenumbers.__version__})")

    def info(title: str, value, confidence=Confidence.HIGH, notes: str = "") -> Finding:
        ctx.emit(f"[+] {title}: {value}")
        return Finding(module=NAME, title=title, value=str(value), source="phonenumbers",
                       confidence=confidence, result=ResultKind.INFO, notes=notes)

    valid = phonenumbers.is_valid_number(number)
    findings = [
        info("Valid number", "Yes" if valid else "No",
             notes="" if valid else "Not a valid number for its country plan (e.g. a fictional +1 555 number)."),
        info("Possible number", "Yes" if phonenumbers.is_possible_number(number) else "No"),
        info("International format", phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL)),
        info("Country calling code", f"+{number.country_code}"),
    ]
    region = phonenumbers.region_code_for_number(number)
    if region:
        country = geocoder.country_name_for_number(number, "en")
        findings.append(info("Country", f"{country} ({region})" if country else region))
    area = geocoder.description_for_number(number, "en")
    if area and area != geocoder.country_name_for_number(number, "en"):
        findings.append(info("Region", area, Confidence.MEDIUM, "Area from the number's prefix, not a location."))
    line_type = types.get(phonenumbers.number_type(number), "unknown")
    findings.append(info("Line type", line_type, Confidence.MEDIUM))
    operator = carrier.name_for_number(number, "en")
    if operator:
        findings.append(info("Carrier (original allocation)", operator, Confidence.LOW,
                             "Ported numbers may show the wrong carrier."))
    zones = [z for z in timezone.time_zones_for_number(number) if z != "Etc/Unknown"]
    if zones:
        findings.append(info("Time zone", ", ".join(zones), Confidence.MEDIUM))
    return findings


MODULE = ModuleSpec(
    number="03",
    id="phoneintel",
    name=NAME,
    icon="phone",
    description="Validity, country, region, carrier, line type and time zone.",
    labels=("local",),
    target_types=(TargetType.PHONE,),
    provider="Nothing leaves this computer (offline library)",
    run=run,
    engine_name="phonenumbers (offline)",
    tools=("phoneinfoga",),
    timeout_s=30,
    notes="Carrier data reflects the original allocation.",
)
