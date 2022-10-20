import os, sys, time

def Spinner():
	l = ['|', '/', '-', '\\']
	for i in l+l+l:
		#sys.stdout.write(f"""\r{y}[{b}#{y}]{w} Loading... {i}""")
		sys.stdout.flush()
		time.sleep(0.0)


def clear():
    system = os.name
    if system == 'nt':
        os.system('cls')
    elif system == 'posix':
        os.system('clear')
    else:
        print('\n'*120)
    return

def transition():
    clear()