#!/usr/bin/env python3
# simple-mhl - Modern verification and sealing tool for legacy MHL files

import os, sys
import click, getpass, platform, hashlib, xxhash

try:
    from lxml import etree
except ImportError:
    sys.exit(1)
from datetime import datetime, timezone

VERSION = "1.0"
MHL_NS = "http://www.mediahashlist.org/v1.1"

# MHL v1.1 XSD (XMLDSig stripped so it works offline)
MHL_XSD = f"""
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" 
           targetNamespace="{MHL_NS}" 
           xmlns="{MHL_NS}" 
           elementFormDefault="qualified">
  <xs:simpleType name="md5Type"><xs:restriction base="xs:hexBinary"><xs:length value="16"/></xs:restriction></xs:simpleType>
  <xs:simpleType name="sha1Type"><xs:restriction base="xs:hexBinary"><xs:length value="20"/></xs:restriction></xs:simpleType>
  <xs:simpleType name="xxhashType"><xs:restriction base="xs:integer"><xs:totalDigits value="10"/></xs:restriction></xs:simpleType>
  <xs:simpleType name="xxhash64Type"><xs:restriction base="xs:hexBinary"><xs:length value="8"/></xs:restriction></xs:simpleType>
  <xs:simpleType name="versionType"><xs:restriction base="xs:decimal"><xs:fractionDigits value="1"/><xs:minInclusive value="0"/></xs:restriction></xs:simpleType>
  <xs:element name="creationdate" type="xs:dateTime"/>
  <xs:element name="file" type="xs:string"/>
  <xs:element name="size" type="xs:positiveInteger"/>
  <xs:element name="lastmodificationdate" type="xs:dateTime"/>
  <xs:element name="hashdate" type="xs:dateTime"/>
  <xs:element name="name" type="xs:string"/>
  <xs:element name="username" type="xs:string"/>
  <xs:element name="hostname" type="xs:string"/>
  <xs:element name="tool" type="xs:string"/>
  <xs:element name="source" type="xs:string"/>
  <xs:element name="startdate" type="xs:dateTime"/>
  <xs:element name="finishdate" type="xs:dateTime"/>
  <xs:element name="log" type="xs:string"/>
  <xs:attribute name="version" type="versionType"/>
  <xs:attribute name="referencehhashlist" type="xs:boolean"/>
  <xs:element name="md5"><xs:complexType><xs:simpleContent><xs:extension base="md5Type"/></xs:simpleContent></xs:complexType></xs:element>
  <xs:element name="sha1"><xs:complexType><xs:simpleContent><xs:extension base="sha1Type"/></xs:simpleContent></xs:complexType></xs:element>
  <xs:element name="xxhash"><xs:complexType><xs:simpleContent><xs:extension base="xxhashType"/></xs:simpleContent></xs:complexType></xs:element>
  <xs:element name="xxhash64"><xs:complexType><xs:simpleContent><xs:extension base="xxhash64Type"/></xs:simpleContent></xs:complexType></xs:element>
  <xs:element name="xxhash64be"><xs:complexType><xs:simpleContent><xs:extension base="xxhash64Type"/></xs:simpleContent></xs:complexType></xs:element>
  <xs:element name="null" type="xs:string" fixed=""/>
  <xs:element name="creatorinfo">
    <xs:complexType><xs:sequence>
      <xs:element ref="name" minOccurs="0" maxOccurs="1"/>
      <xs:element ref="username" minOccurs="1" maxOccurs="1"/>
      <xs:element ref="hostname" minOccurs="1" maxOccurs="1"/>
      <xs:element ref="tool" minOccurs="1" maxOccurs="1"/>
      <xs:element ref="source" minOccurs="0" maxOccurs="1"/>
      <xs:element ref="startdate" minOccurs="1" maxOccurs="1"/>
      <xs:element ref="finishdate" minOccurs="1" maxOccurs="1"/>
      <xs:element ref="log" minOccurs="0" maxOccurs="1"/>
    </xs:sequence></xs:complexType>
  </xs:element>
  <xs:element name="hash">
    <xs:complexType><xs:sequence>
      <xs:element ref="file" minOccurs="1" maxOccurs="1"/>
      <xs:element ref="size" minOccurs="1" maxOccurs="1"/>
      <xs:element ref="creationdate" minOccurs="0" maxOccurs="1"/>
      <xs:element ref="lastmodificationdate"/>
      <xs:choice minOccurs="1" maxOccurs="unbounded">
        <xs:element ref="md5"/><xs:element ref="sha1"/><xs:element ref="xxhash"/><xs:element ref="xxhash64"/><xs:element ref="xxhash64be"/><xs:element ref="null"/>
      </xs:choice>
      <xs:element ref="hashdate"/>
    </xs:sequence><xs:attribute ref="referencehhashlist"/></xs:complexType>
  </xs:element>
  <xs:element name="hashlist">
    <xs:complexType><xs:sequence>
      <xs:element ref="creationdate" minOccurs="0" maxOccurs="1"/>
      <xs:element ref="creatorinfo" minOccurs="1" maxOccurs="1"/>
      <xs:element ref="hash" minOccurs="1" maxOccurs="unbounded"/>
    </xs:sequence><xs:attribute name="version" type="versionType" use="required"/></xs:complexType>
  </xs:element>
</xs:schema>
"""

# Help menu
class SimpleMHLHelp(click.Group):
    def format_help(self, ctx, formatter):
        click.echo(f"simple-mhl v{VERSION}. Modern verification and sealing tool for legacy MHL files")
        click.echo("\nUsage: simple-mhl <command> [options] <path>")
        click.echo("\nCommands & Options:")
        click.echo("  seal               : Seal directory (MHL file will be generated at the root)")
        click.echo("    -a, --algorithm  : Algorithm: xxhash (default), md5, sha1, xxh128, xxh3_64")
        click.echo("    --dont-reseal    : Abort operation if an MHL file already exists at root")
        click.echo("  verify             : Verify an MHL file and hash values")
        click.echo("    -s, --schema     : Validate XML against MHL v1.1 XSD")
        click.echo("  -h, --help         : Show this help message")
        click.echo("  --version          : Print version")

class SealCommandHelp(click.Command):
    def format_help(self, ctx, formatter):
        help_text = (
            "Usage: simple-mhl seal [options] <directory>\n\n"
            "Options:\n"
            "  -a, --algorithm   : Algorithm: xxhash (default), md5, sha1, xxh128, xxh3_64\n"
            "  --dont-reseal     : Abort operation if an MHL file already exists at root\n"
            "  -h, --help        : Show this message\n"
        )
        click.echo(help_text, nl=False)

class VerifyCommandHelp(click.Command):
    def format_help(self, ctx, formatter):
        help_text = (
            "Usage: simple-mhl verify [options] <file.mhl>\n\n"
            "Options:\n"
            "  -s, --schema      : Validate XML against MHL v1.1 XSD\n"
            "  -h, --help        : Show this message\n"
        )
        click.echo(help_text, nl=False)

# Define hash algorithms
def get_hash(filepath, algo_key):
    mapping = {
        "xxhash": xxhash.xxh64,
        "xxh64": xxhash.xxh64, "xxhash64": xxhash.xxh64, "xxhash64be": xxhash.xxh64,
        "xxh128": xxhash.xxh3_128, "xxhash128": xxhash.xxh3_128,
        "xxh3_64": xxhash.xxh3_64, "xxhash3_64": xxhash.xxh3_64,
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
    }
    if algo_key not in mapping:
        raise ValueError(f"Unsupported hash algorithm: {algo_key}")

    # Instantiate the hasher and reads the file in 64KB chunks to maintain a low memory footprint.
    hasher = mapping[algo_key]()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): hasher.update(chunk)
    return hasher.hexdigest()

# CLI Group Definition
@click.group(cls=SimpleMHLHelp, context_settings={'help_option_names': ['-h', '--help']})
@click.version_option(VERSION, '--version')
def cli(): pass

# ------------ Seal command ------------
@cli.command(cls=SealCommandHelp)
@click.argument('root', type=click.Path(exists=True))
@click.option('--algorithm', '-a', default='xxhash')
@click.option('--dont-reseal', is_flag=True)
def seal(root, algorithm, dont_reseal):
    # Resolve absolute path
    root = os.path.abspath(root)
    base_name = os.path.basename(root)

    # Generate timestamp
    now_dt = datetime.now(timezone.utc)
    timestamp = now_dt.strftime("%Y-%m-%d_%H%M%S")
    mhl_name = f"{base_name}_{timestamp}.mhl"
    mhl_path = os.path.join(root, mhl_name)
    
    # Handle filename collisions
    if os.path.exists(mhl_path):
        if dont_reseal: sys.exit(0)
        counter = 1
        while os.path.exists(os.path.join(root, f"{base_name}_{timestamp}_{counter}.mhl")):
            counter += 1
        mhl_path = os.path.join(root, f"{base_name}_{timestamp}_{counter}.mhl")

    # Initialise XML root element and populate the creatorinfo block
    now_iso = now_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    doc = etree.Element(f"{{{MHL_NS}}}hashlist", version="1.1", nsmap={None: MHL_NS})
    etree.SubElement(doc, f"{{{MHL_NS}}}creationdate").text = now_iso
    info = etree.SubElement(doc, f"{{{MHL_NS}}}creatorinfo")
    for k, v in [("username", getpass.getuser()), ("hostname", platform.node()), ("tool", f"simple-mhl v{VERSION}"), ("startdate", now_iso), ("finishdate", now_iso)]:
        etree.SubElement(info, f"{{{MHL_NS}}}{k}").text = v
    xml_tag = 'xxhash64be' if algorithm in ['xxhash', 'xxh64'] else algorithm.replace('xxh', 'xxhash')

    # Construct hash entries, ignoring hidden files
    for dirpath, dirnames, filenames in os.walk(root):
        # Modify dirnames in-place to skip hidden directories.
        dirnames[:] = sorted([d for d in dirnames if not d.startswith('.')])
        
        for filename in sorted(filenames):
            if filename.startswith('.'): 
                continue
            
            filepath = os.path.join(dirpath, filename)
            
            # Calculate relative path for the XML manifest
            rel_path = os.path.relpath(filepath, root)
            
            # Get file statistics
            stat_result = os.stat(filepath)
            
            h_el = etree.SubElement(doc, f"{{{MHL_NS}}}hash")
            etree.SubElement(h_el, f"{{{MHL_NS}}}file").text = rel_path.replace('\\', '/')
            etree.SubElement(h_el, f"{{{MHL_NS}}}size").text = str(stat_result.st_size)
            mtime_utc = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
            etree.SubElement(h_el, f"{{{MHL_NS}}}lastmodificationdate").text = mtime_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
            etree.SubElement(h_el, f"{{{MHL_NS}}}{xml_tag}").text = get_hash(filepath, algorithm)
            etree.SubElement(h_el, f"{{{MHL_NS}}}hashdate").text = now_iso
            
    # Serialise the constructed XML tree to disk with formatting
    etree.ElementTree(doc).write(mhl_path, xml_declaration=True, encoding='UTF-8', pretty_print=True)

# ------------ Verify command ------------
@cli.command(cls=VerifyCommandHelp)
@click.argument('mhl_file', type=click.Path(exists=True))
@click.option('--schema', '-s', is_flag=True)
def verify(mhl_file, schema):
    errors, schema_ok = [], True
    try:
        # Parse the MHL file into a tree and conditionally evaluates it against the  XSD
        tree = etree.parse(mhl_file)
        if schema:
            xsd_doc = etree.XML(MHL_XSD.encode('utf-8'))
            xsd = etree.XMLSchema(xsd_doc)
            if not xsd.validate(tree):
                schema_ok = False
                for err in xsd.error_log:
                    sys.stderr.write(f"Schema Error: {err.message.replace(f'{{{MHL_NS}}}', '')} (line {err.line})\n")

        # Compare the declared payloads with the actual files
        hashes = tree.xpath("//*[local-name()='hash']")
        for h in hashes:
            # Extract the filename and skip the block if the file definition is missing
            fname_list = h.xpath(".//*[local-name()='file']/text()")
            if not fname_list: continue
            fname = fname_list[0]
            
            # Scan for supported hash algorithm tags
            h_nodes = h.xpath(".//*[local-name()='md5' or local-name()='sha1' or local-name()='xxhash' or local-name()='xxhash64' or local-name()='xxhash64be' or local-name()='xxhash128' or local-name()='xxhash3_64' or local-name()='null']")
            if not h_nodes:
                errors.append(f"No supported hash found for: {fname}")
                continue

            # Extract the specific tag string and its hex value
            h_node = h_nodes[0]
            tag = h_node.tag.split('}')[-1] if '}' in h_node.tag else h_node.tag
            expected = h_node.text
            fpath = os.path.join(os.path.dirname(mhl_file), fname)
            
            # Compare hashes (verify physical existence on disk first)
            if not os.path.exists(fpath):
                errors.append(f"Missing file: {fname} cannot be found")
                continue
            calculated_hex = get_hash(fpath, tag)
            # Legacy check: <xxhash> was integer in some legacy MHL
            if tag == "xxhash" and expected.isdigit():
                if str(int(calculated_hex, 16)) != expected:
                    errors.append(fname)
            else:
                # Standard hex-to-hex comparison for all other tags
                if calculated_hex != expected:
                    errors.append(fname)

        # Exit with specific error codes
        if errors:
            click.echo("\n".join(errors))
            sys.exit(40 if not schema_ok and not [e for e in errors if "Missing" not in e] else 30)
        
        sys.exit(10 if not schema_ok else 0)
    except Exception as e:
        # Trap fatal execution errors for debugging
        sys.stderr.write(f"Verification Error: '{str(e)}'\n")
        raise


# Boilerplate: direct execution only
if __name__ == "__main__":
    cli()