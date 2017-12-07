#!/usr/bin/python -u

"""
known issues

1. works with Satellite and has rhnSQL dependency :(
2. strictly follows architecture so things like upgrade from x86_64 to noarch are not possible
3. doesn't follow obsoletes of packages
4. looks only for security advisories but according to errata tool there are almost 400 RHBAs with CVE attached
5. can be probably written in one select, split into multiple to improve readability of the alrgorithm
6. can be optimized for performance
"""

from optparse import Option, OptionParser

import decimal
import psycopg2
import sys

DEFAULT_DB_NAME = "rhnschema"
DEFAULT_DB_USER = "rhnuser"
DEFAULT_DB_PASSWORD = "rhnpw"
DEFAULT_DB_HOST = "localhost"
DEFAULT_DB_PORT = 5432


def _dict(row=None, description=None):
  """
  converts array into dict
  @param row: array to be converted
  @param description: array description which will be used as dict keys
  """
  if not description:
    raise AttributeError('Need dictionary description')
  data = {}
  if row is None:
    return None
  for i in range(len(row)):
    if isinstance(row[i], decimal.Decimal):
      data[description[i][0]] = int(row[i])
    else:
      data[description[i][0]] = row[i]
  return data


def splitFilename(filename):
    """
    Pass in a standard style rpm fullname 

    Return a name, version, release, epoch, arch, e.g.::
        foo-1.0-1.i386.rpm returns foo, 1.0, 1, i386
        1:bar-9-123a.ia64.rpm returns bar, 9, 123a, 1, ia64
    """

    if filename[-4:] == '.rpm':
        filename = filename[:-4]

    archIndex = filename.rfind('.')
    arch = filename[archIndex + 1:]

    relIndex = filename[:archIndex].rfind('-')
    rel = filename[relIndex + 1:archIndex]

    verIndex = filename[:relIndex].rfind('-')
    ver = filename[verIndex + 1:relIndex]

    epochIndex = filename.find(':')
    if epochIndex == -1:
        epoch = ''
    else:
        epoch = filename[:epochIndex]

    name = filename[epochIndex + 1:verIndex]
    return name, ver, rel, epoch, arch

def init_db(db_name, db_user, db_pass, db_host, db_port):
    connection = psycopg2.connect(database=db_name, user=db_user, password=db_pass, host=db_host, port=db_port)
    return connection.cursor()

"""
finds all channels that contain the RPM we're searching for
"""
def get_channels(cur, n, v, r, e, a):
    the_sql = """
        select channel_id, package_id
        from rhnchannelpackage
        where package_id = (select id from rhnpackage where name_id = (select id from rhnpackagename where name = %(name)s)
        and evr_id = (select id from rhnpackageevr where ((epoch is null and %(epoch)s is null) or epoch = %(epoch)s)
        and version = %(version)s and release = %(release)s)
        and package_arch_id = LOOKUP_PACKAGE_ARCH(%(arch)s))
        """
    cur.execute(the_sql, {'name' : n, 'version' : v, 'release' : r, 'epoch' : e, 'arch' : a})
    res = [_dict(x, cur.description) for x in cur.fetchall()]
    return res

"""
finds channel family where the channel(s) the RPM is present belong to
"""
def get_channel_families(cur, channels):
    the_sql = """
        select f.id, f.label
        from rhnchannelfamily f
        join rhnchannelfamilymembers fm on f.id = fm.channel_family_id
        where fm.channel_id in %(channels)s
        """
    cur.execute(the_sql, {'channels' : channels})
    res = [_dict(x, cur.description) for x in cur.fetchall()]
    return res

"""
finds all packages with higher nevra present in channels with the same channel family
from RPM logic all packages with higher nevra are upgrades
"""
def get_result(cur, n, v, r, e, a, families):
    the_sql = """
        select rhnchannelfamily.label, rhnchannel.label, package_id
        from rhnchannelpackage join rhnchannel on rhnchannelpackage.channel_id = rhnchannel.id
        join rhnchannelfamilymembers on rhnchannelfamilymembers.channel_id = rhnchannel.id
        join rhnchannelfamily on rhnchannelfamily.id = rhnchannelfamilymembers.channel_family_id and rhnchannelfamily.id in %(families)s
        where package_id in (select rhnpackage.id from rhnpackage join rhnpackageevr on rhnpackage.evr_id = rhnpackageevr.id where name_id in (select id from rhnpackagename where name = %(name)s)
        and package_arch_id = LOOKUP_PACKAGE_ARCH(%(arch)s)
        and rhnpackageevr.evr > (select evr from rhnpackageevr where ((epoch is null and %(epoch)s is null or epoch = %(epoch)s)) and version = %(version)s and release = %(release)s))
    """
    cur.execute(the_sql, {'name' : n, 'version' : v, 'release' : r, 'epoch' : e, 'arch' : a, 'families' : families})
    res = [_dict(x, cur.description) for x in cur.fetchall()]
    return res

"""
returns all security advisories which are linked to the upgradeable packages
"""
def get_erratas(cur, packages):
    the_sql = """
    select e.advisory_name, ep.package_id from rhnerrata e join rhnerratapackage ep on e.id = ep.errata_id where advisory_type = 'Security Advisory' and ep.package_id in %(packages)s
    """
    cur.execute(the_sql, {'packages' : packages})
    res = [_dict(x, cur.description) for x in cur.fetchall()]
    return res

"""
similar to get_erratas with addition of channel and nevra of the package
"""
def get_all(cur, packages):
    the_sql = """
    select e.advisory_name, ep.package_id, evr.evr, c.label from rhnerrata e join rhnerratapackage ep on e.id = ep.errata_id left join rhnpackage p on ep.package_id = p.id join rhnpackageevr evr on p.evr_id = evr.id left join rhnchannelpackage cp on cp.package_id = p.id join rhnchannel c on c.id = cp.channel_id where advisory_type = 'Security Advisory' and ep.package_id in %(packages)s
    """
    cur.execute(the_sql, {'packages' : packages})
    res = [_dict(x, cur.description) for x in cur.fetchall()]
    return res

def process(filename, cursor):
    n, v, r, e, a = splitFilename(filename)
    if e == '':
        e = None

    channels = get_channels(cursor, n, v, r, e, a)
    families = get_channel_families(cursor, tuple(set([ x['channel_id'] for x in channels])))
    packages = get_result(cursor, n, v, r, e, a, tuple(set([ x['id'] for x in families])))
    get_erratas(cursor, tuple(set([ x['package_id'] for x in packages])))
    res = get_all(cursor, tuple(set([ x['package_id'] for x in packages])))
    return res

def main():
    optionsTable = [
        Option('-d', '--dbname', action='store', dest='db_name', default=DEFAULT_DB_NAME,
            help='database name to connect to (default: "rhnschema")'),
        Option('-U', '--username', action='store', dest='db_user', default=DEFAULT_DB_USER,
            help='database user name (default: "rhnuser")'),
        Option('-W', '--password', action='store', dest='db_pass', default=DEFAULT_DB_PASSWORD,
            help='password to use (default: "rhnuser")'),
        Option('--host', action='store', dest='db_host', default=DEFAULT_DB_HOST,
            help='database server host or socket directory (default: "local socket")'),
        Option('-p', '--port', action='store', dest='db_port', default=DEFAULT_DB_PORT,
            help='database server port (default: "5432")'),
    ]

    optionParser = OptionParser(
        usage="Usage: %s [--dbname=<dbname>] [--username=<username>] [--password=<password>] [--host=<host>] [--port=<port>] rpm_name" % sys.argv[0],
        option_list=optionsTable)

    options, unparsed = optionParser.parse_args(sys.argv[1:])

    if not len(unparsed) >= 1:
        print("Missing rpm_name. Exiting.")
        sys.exit(1)

    cursor = init_db(options.db_name, options.db_user, options.db_pass, options.db_host, options.db_port)
    res = process(unparsed[0], cursor)

    for item in res:
        print(item)

if __name__ == '__main__':
    main()
