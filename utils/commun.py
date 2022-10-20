import os
try: 
    from pystyle import Colors, Colorate, Write, Box
except:
    os.system('pip install pystyle && cls')
    from pystyle import Colors, Colorate, Write, Box


def print_title():

    print(Colorate.Horizontal(Colors.blue_to_purple,  '''
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

                    ██╗   ██╗██████╗      ██████╗  ███████╗ ███████╗ ██╗ ██████╗  ███████╗ ███████╗
                    ██║   ██║██╔══██╗     ██╔══██╗ ██╔════╝ ██╔════╝ ██║ ██╔══██╗ ██╔════╝ ██╔════╝
                    ██║   ██║██████╔╝     ██║  ██║ █████╗   ███████╗ ██║ ██████╔╝ █████╗   ███████╗
                    ██║   ██║██╔══██╗     ██║  ██║ ██╔══╝   ╚════██║ ██║ ██╔══██╗ ██╔══╝   ╚════██║
                    ╚██████╔╝██║  ██║     ██████╔╝ ███████╗ ███████║ ██║ ██║  ██║ ███████╗ ███████║
                     ╚═════╝ ╚═╝  ╚═╝     ╚═════╝  ╚══════╝ ╚══════╝ ╚═╝ ╚═╝  ╚═╝ ╚══════╝ ╚══════╝

                                        discord.gg/urdesires | Developed by ziue
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


'''))


# Print main message
def print_banner():
    print_title()
    banner2 = Colorate.Horizontal(Colors.blue_to_purple,  '''\n
                                        [1] BOOSTING TOOL           [5] REMOVE DUPLICATES
                                        [2] TOKEN CHECKER           [6] CAPTCHA BALANCE
                                        [3] SERVER JOINER           [7] MAIN MENU
                                        [4] TOKEN SETTINGS          [8] EXIT''')   
    print(banner2)

# Authentication message
def auth_banner():
    print_title()
    auth = Colorate.Horizontal(Colors.blue_to_purple,  '''\n
            [1] LOGIN
            [2] REGISTER
            [3] FORGOT PASSWORD
            [4] EXIT APPLICATION
        ''')
    print(auth)

# Print main message
def print_admin_banner():
    print_title()
    banner2 = Colorate.Horizontal(Colors.blue_to_purple,  '''
            [1] Fetch user information
            [2] Change user password
            [3] Get HWID from user
            [4] Reset user HWID
            [5] Delete user
            [6] Get users
            [7] Admin Menu
            [8] Main Menu
    ''')   
    print(banner2)

