import pathlib
import click
import pefile
import tempfile

PE_MAGIC = b'MZ\x90\x00\x03\x00\x00\x00'


def extract_pe(data, base_path):
    pe = pefile.PE(data=data)

    # calculate actual size of the PE file
    pe_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    for section in pe.sections:
        pe_size += section.SizeOfRawData

    # write the PE file to a temporary file
    filename = tempfile.mktemp(suffix='.dll', dir=base_path)
    with open(filename, 'wb') as f:
        f.write(data[:pe_size])
        print(f'Extracted PE file to {filename}')


@click.command()
@click.argument("input", type=click.Path(exists=True))
def main(input):
    with open(input, 'rb') as f:
        data = f.read()

    # iterate over the file and find the PE header
    for i in range(len(data) - len(PE_MAGIC)):
        if data[i:i + len(PE_MAGIC)] == PE_MAGIC:
            extract_pe(data[i:], pathlib.Path(input).parents[0])


if __name__ == '__main__':
    main()
