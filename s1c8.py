import codecs

from s1c6 import split


def unique_blocks(t):
    return len(set(split(16, t)))


def main():
    texts = [codecs.decode(line.strip(), "hex") for line in open('set1/8.txt')]

    mapped = ((unique_blocks(t), t) for t in texts)

    score, text = min(mapped)

    print(score, codecs.encode(text, 'hex'))


if __name__ == '__main__':
    main()
