"""
Strict datetime parse utilities.
"""
from datetime import datetime
from pytz import FixedOffset, UTC
from re import compile as re_compile

# Month-name to month-value map
_month_names = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

# ISO 8601 timestamp format regex (includes RFC 3339)
_iso_8601_regex = re_compile(
    r"^(?P<year>[0-9]{4})-?"
    r"(?P<month>0[1-9]|1[0-2])-?"
    r"(?P<day>0[1-9]|[12][0-9]|3[01])"
    r"[Tt ]"
    r"(?P<hour>[01][0-9]|2[0-3]):?"
    r"(?P<minute>[0-5][0-9]):?"
    r"(?P<second>[0-5][0-9]|6[01])"
    r"(?P<frac_sec>[\.,][0-9]+)?"
    r"(?P<timezone>[-+][01][0-9]:?[0-5][0-9]|[Zz])$")

# RFC 2282 timestamp format regex
_rfc_2282_regex = re_compile(
    r"^(?:(?P<dow>Mon|Tue|Wed|Thu|Fri|Sate|Sun)\s*,)?\s*"
    r"(?P<day>[0-9]|0[1-9]|1[0-9]|2[0-9]|3[01])\s+"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<year>[0-9]{4})\s+"
    r"(?P<hour>[01][0-9]|2[0-3]):"
    r"(?P<minute>[0-5][0-9]):"
    r"(?P<second>[0-5][0-9]|6[01])\s+"
    r"(?P<timezone>[-+][01][0-9][0-5][0-9])$"
)

def parse_iso8601(s):
    """
    Parse a timestamp formatted in ISO 8601 timestamp format and return a
    Timestamp object. If the string is not a valid ISO 8601 timestmap, None
    is returned.

    ISO 8601 timestamps include the forms:
        2018-12-25T14:00:00-08:00
        20181225T140000-0800            (Condensed)
        20181225T230000+0100            (Timestamp sign *must* be present)
        2018-12-25T22:00:00Z            (Z == +0000, UTC)
        20181225T220000Z                (Condensed)
        20181225 220000Z                (Space instead of T)

    Condensing of dates and times/zone offsets may be mixed, and case of 
    'T' and 'Z' is insignficant:
        2018-12-25 220000z
        20181225t14:00:00-08:00
    etc.

    If fractional seconds are included, they are ignored.
    """
    m = _iso_8601_regex.match(s)
    if not m:
        return None

    zone = m.group("timezone")
    if zone in ("Z", "z"):
        offset = UTC
    else:
        zone = zone.replace(":", "")
        assert len(zone) == 5
        sign = zone[0]
        offset_hour = int(zone[1:3])
        offset_minutes = offset_hour * 60 + int(zone[3:5])

        if sign == "-":
            offset_minutes = -offset_minutes
        
        offset = FixedOffset(offset_minutes)

    return datetime(
        year=int(m.group("year")),
        month=int(m.group("month")),
        day=int(m.group("day")),
        hour=int(m.group("hour")),
        minute=int(m.group("minute")),
        second=int(m.group("second")),
        tzinfo=offset)

def parse_rfc2282(s):
    """
    Parse a timestamp formatted in RFC 2282 timestamp format and return a
    Timestamp object. If the string is not a valid RFC 2282 timestmap, None
    is returned.

    RFC 2282 timestamps are of the form:
        Tue, 25 Dec 2018 14:00:00 -0800
        25 Dec 2018 14:00:00 -0800
    """
    m = _rfc_2282_regex.match(s)
    if not m:
        return None

    month = _month_names[m]
    zone = m.group("timezone")
    assert len(zone) == 5
    sign = zone[0]
    offset_hour = int(zone[1:3])
    offset_minutes = offset_hour * 60 + int(zone[3:5])

    if sign == "-":
        offset_minutes = -offset_minutes
    
    if offset_minutes == 0:
        offset = UTC
    else:
        offset = FixedOffset(offset_minutes)

    return datetime(
        year=int(m.group("year")),
        month=month,
        day=int(m.group("day")),
        hour=int(m.group("hour")),
        minute=int(m.group("minute")),
        second=int(m.group("second")),
        tzinfo=offset)

def is_leap_year(year):
    """
    Indicates whether the specified year is a leap year.

    Every year divisible by 4 is a leap year -- 1912, 1996, 2016, 2032, etc.,
    are leap years -- UNLESS the year is divisible by 100 AND NOT by 400. Thus,
    1200, 1600, 2000, 2400, etc., are leap years, while 1800, 1900, 2100, etc.,
    are not.

    Why do we have this logic?
    This is because the earth orbits the sun in approximately 365.2425 days.
    Over 400 orbits, that comes out to 146,097 days (365.2425 * 400).

    Ignoring the century rule (making every fourth year a leap year, including
    1800, 1900, etc.), gives us 146,100 days, overcounting by 3 days every
    400 years. Thus, making 3 out of every 4 century boundaries non-leap years
    fixes this overcounting.
    """
    return year % 400 == 0 or (year % 4 == 0 and year % 100 != 0)
