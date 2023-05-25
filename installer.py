from colorama import init, Fore, Style
import subprocess

# class bcolors:
#     HEADER = '\033[95m'
#     OKBLUE = '\033[94m'
#     OKCYAN = '\033[96m'
#     OKGREEN = '\033[92m'
#     WARNING = '\033[93m'
#     FAIL = '\033[91m'
#     ENDC = '\033[0m'
#     BOLD = '\033[1m'
#     UNDERLINE = '\033[4m'

# BLACK = '\033[30m'
# RED = '\033[31m'
# GREEN = '\033[32m'
# YELLOW = '\033[33m'
# BLUE = '\033[34m'
# MAGENTA = '\033[35m'
# CYAN = '\033[36m'
# WHITE = '\033[37m'
# RESET = '\033[0m'

IMPORTLIB = ["volatility3", "requests", "pefile>=2017.8.1", "yara-python>=3.8.0", "capstone>=3.0.5", "pycryptodome", "leechcorepyc>=2.4.0", "flask"]

def flushScreen():
    for _ in range(30):
        print("\n")

def main():
    flushScreen()
    upper = "```````````````````````````````````````````````````````````````````````````````````````````````````````"
    bottom = "```````````````````````````````````````````````````````````````````````````````````````````````````````"
    banner = """
        .?77?!    ~?7?:  :?7?~!?77777777J~ .~77???7!: .J777    !?7J: :!7???77!:  :?7?!    :J77777777??  
        ?J7J!Y~   ?J!Y^  ^Y!J7~?77Y77Y77?^~J7??7!?J7J7 7J!Y!  ~Y!J7 7J7??!!??7J! :Y!??    .?77J?!J?777  
        7J!JY?7Y:  7J!Y^  ^Y!?7   .Y77Y   :Y!7Y.   ??!Y! ??!Y^:Y!?J ^Y!?J    J?!Y^:Y!??        7J!Y^     
        ~Y!JJ!5!7Y. ?J!Y^  ^Y!??   .Y77Y   :Y!7J    7J!J! .J77YY77Y. ~Y!??    ??!Y^:Y!??        7J!Y^     
        :Y!?J???J!?J ~Y7??~~??7Y~   .Y!7Y    7J7?7~^!J7?J.  :Y7??!Y:  .?J7J7~~7J7J? :Y!?J~~~!!   7J!Y^     
        .JJ?J:   ~J?Y! ^7??JJ??7^    .J?JJ     ^7??JJJ?7~     ^J??J~     ~7??JJ??7^  :Y??JJJJJY.  !Y?Y^     
        ...      ....    .....        ..         .....        ....         ....      ........     ...      

    """

    init()

    # print(f"{bcolors.WARNING} banner {bcolors.ENDC}")
    # print(RED + "This is red text.")
    print(f"{Fore.RED} {upper}")
    print(f"{Fore.BLUE} {Style.DIM} {banner}")
    print(f"{Fore.RED} {bottom}")

    inp = input(f"{Fore.LIGHTGREEN_EX} Do you want to install AutoVolt? [y/N] \n>")

    if inp.lower() == 'y':
        try:
            totalLib = len(IMPORTLIB)

            for idx, lib in enumerate(IMPORTLIB):
                idx += 1
                print(f"{Fore.LIGHTGREEN_EX} Importing File {lib} ({idx}/{totalLib})")
                subprocess.check_call(["pip", "install", lib])
        except ImportError as e:
            print(f"{Fore.RED} [!] Error : {e}")
    
    print()
    print(f"{Fore.LIGHTGREEN_EX} Created by Fast, Sansaga and Mbuh 2023")

if __name__ == '__main__':
    main()