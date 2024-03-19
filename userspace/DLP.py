import re


def check_for_code_c(message, to_print=False, sanitize_newline=True, threshold=0.8):
    assert type(message) == str, 'ERROR: got wrong type of message'

    total_score = 0

    # for regex convenience
    message = message.replace('\r\n', '\n')

    if sanitize_newline:
        message = message.replace('\\n', '\n')

    if to_print:
        print(message)

    keys = get_regex_keys()

    for key in keys:
        expression = key[0]
        score = key[1]
        # check if key in line
        matches = re.findall(expression, message, re.MULTILINE)
        total_score += len(matches) * score
        if len(matches) > 0 and to_print:
            print(expression)

    lines = [line for line in message.splitlines() if len(line.lstrip()) > 0]
    total_lines = len(lines)

    if total_lines == 0:  # prevent division by zero
        return False  # the only text is spaces, tabs, and newlines

    normalized_score = total_score / total_lines
    if to_print:
        print(normalized_score)

    if normalized_score >= threshold:
        return True
    else:
        return False


def get_regex_keys():
    keys = list()  # keys are (key, starting_index, end_index, score)
    # macros
    keys.append((r'^[ \t]*# ?include ?[<"].*[>"] *$', 100))
    keys.append((r'^[ \t]*# ?define', 40))
    # code functions
    keys.append((r'^[ \t]*for ?\(', 10))
    keys.append((r'^[ \t]*for ?\( ? int', 50))
    keys.append((r'^[ \t]*if ?\(', 2))
    keys.append((r'^[ \t]*else]', 2))
    keys.append((r'^[ \t]*return ', 2))
    keys.append((r'^[ \t]*struct ', 20))
    keys.append((r'^[ \t]*inline ', 30))
    keys.append((r'^[ \t]*typedef ', 50))
    keys.append((r'^[ \t]*(int|void) main\(\)', 50))
    keys.append((r'^[ \t]*(int|void) main\(void\)', 100))
    keys.append((r'^[ \t]*(int|void) main\(int argc, char \*\*argv\)', 200))

    # syntax
    keys.append((r';$', 0.5))
    keys.append((r'\);$', 2))
    keys.append((r'^[ \t]*{$', 5))
    keys.append((r'^[ \t]*}$', 5))
    keys.append((r'\) ?{$', 5))
    keys.append((r'\(int .*\) ?{$', 30))
    keys.append((r'^[ \t]*void.*\(\)$', 30))
    keys.append((r'^[ \t]*void.*\(\) ?{$', 100))
    # documentation
    keys.append((r'^[ \t]*//', 5))
    keys.append((r'^[ \t]*/\*', 5))
    keys.append((r'^[ \t]*/\*\*', 5))
    keys.append((r'^[ \t]\*\*/', 5))

    keys.append((r'[ \t\(]i ?= ?0', 10))
    keys.append((r' <= ', 1))
    keys.append((r' >= ', 1))
    keys.append((r' == ', 3))
    keys.append((r' \+= ', 3))
    keys.append((r' -= ', 3))
    keys.append((r'\(\)', 1))
    keys.append((r'[ =][mc]alloc ?\(', 100))
    keys.append((r'printf\(?', 50))
    keys.append((r'scanf\(?', 50))
    keys.append((r'\(".*%d.*"\)', 10))

    data_types = ['signed char', 'unsigned char',
                  'short int', ' signed short', ' signed short int',
                  'unsigned short', 'unsigned short',
                  'int', 'signed', ' signed int', 'unsigned', ' unsigned int',
                  'long int', ' signed long', ' signed long int',
                  'unsigned long', ' unsigned long int',
                  'long long', 'long long', ' signed long long', 'signed long long int',
                  'unsigned long long', ' unsigned long long int', 'long double']

    for dtype in data_types:
        keys.append((r'^' + dtype + '[ [\*]', 10))

    return keys



