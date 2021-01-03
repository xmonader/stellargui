#!/usr/bin/env python3
from tkinter import *
from tkinter.messagebox import *
from tkinter import ttk
import os
import pathlib
import json
import copy
import json
from .stellar import Stellar, PUBLIC_NETWORK_PASSPHRASE, TESTNET_NETWORK_PASSPHRASE
import threading
import webbrowser


NETWORKS_CONSTS = {
    "MAINNET" : {"name": "MAINNET", "network_passphrase": PUBLIC_NETWORK_PASSPHRASE, "horizon": "https://horizon.stellar.org"},
    "TESTNET": {"name": "TESTNET", "network_passphrase": TESTNET_NETWORK_PASSPHRASE, "horizon": "https://horizon-testnet.stellar.org"},
}



# filter fun takes a Path entry
def walk_non_recursive(path: str, filter_fun=lambda x: x):
    """walks non recursively on path

    Args:
        path (str): path to walk over
        filter_fun (Function, optional): filtering function. Defaults to default_filter_fun which accepts anything.
    """
    p = pathlib.Path(path)
    for entry in p.iterdir():
        if filter_fun(entry):
            yield entry


APP_ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),"stellargui.ico")


class StellarGUI:
    def __init__(self):
        self._stellarwallet = None
        self._horizon_server_url = None
        self._networks = {}
        self._wallets = {}
        self.configdir = os.path.expanduser("~/.config/stellargui/")
        self.networks_dir = os.path.expanduser("~/.config/stellargui/networks/")
        self.wallets_dir = os.path.expanduser("~/.config/stellargui/wallets/")

    def prep(self):

        os.makedirs(self.configdir, exist_ok=True)
        os.makedirs(self.networks_dir, exist_ok=True)
        os.makedirs(self.wallets_dir,exist_ok=True)
        self.load_networks()
        self.load_wallets()
        

    def list_all_wallets(self):
        return list(self.load_wallets().keys())

    def list_all_networks(self):
        return list(self.load_networks().keys())


    def save_network(self, network_dict):
        network_file_path = os.path.join(self.networks_dir, f"{network_dict['name']}.json")
        with open(network_file_path, "w") as f:
            json.dump(network_dict, f, indent=4, sort_keys=True)

    def save_wallet(self, wallet_dict):
        wallet_file_path = os.path.join(self.wallets_dir, f"{wallet_dict['name']}.json")
        with open(wallet_file_path, "w") as f:
            json.dump(wallet_dict, f, indent=4, sort_keys=True)


    def delete_wallet(self, name):
        wallet_path = os.path.join(self.wallets_dir, f"{name}.json")
        if os.path.exists(wallet_path):
            try:
                os.remove(wallet_path)
            except Exception as e:
                print(e)


    def load_wallet(self, name):
        wallet_file_path = os.path.join(self.wallets_dir, f"{name}.json")
        with open(wallet_file_path, "w") as f:
            return json.load(f)

    def load_network(self, name):
        network_file_path = os.path.join(self.networks_dir, f"{name}.json")
        with open(network_file_path, "w") as f:
            return json.load(f)

    def load_networks(self):
        self.networks = copy.copy(NETWORKS_CONSTS)
        for e in walk_non_recursive(self.networks_dir):
            str_path = str(e)
            if str_path.endswith(".json"):
                with open(e) as f:
                    try:
                        network = json.load(f)
                        self.networks[network["name"]] = network
                    except Exception as e:
                        print(f"skipping {e}")
        return self.networks


    def load_wallets(self):
        self.wallets = {}
        for e in walk_non_recursive(self.wallets_dir):
            str_path = str(e)
            if str_path.endswith(".json"):
                with open(e) as f:
                    try:
                        wallet = json.load(f)
                        self.wallets[wallet["name"]] = wallet
                    except Exception as e:
                        print(f"skipping {e}")

        return self.wallets
            

    @property
    def wallet(self):
        return self._stellarwallet

    @property
    def wallet_balances(self):
        try:
            return self._stellarwallet.get_balance().balances
        except:
            return []

    @property
    def wallet_assets(self):
        return {b.asset_code: b.asset_issuer for b in self.wallet_balances}

    @property
    def assets_names(self):
        return list(self.wallet_assets.keys())

    def asset_str_from_code(self, code):
        if code == "XLM":
            return code
        return f"{code}:{self.wallet_assets[code]}"

    @property
    def horizon_url(self):
        if not self._horizon_server_url:
            self._horizon_server_url = self._stellarwallet._get_horizon_server().horizon_url
        return self._horizon_server_url

    @property
    def all_wallets_names(self):
        return sorted(list(self.list_all_wallets()))

    def filter_wallets_by_network(self, network="ALL"):
        if network == "ALL":
            return self.all_wallets_names
        else:
            res = []
            for w_name in self.list_all_wallets():
                w = self.wallets[w_name]
                if w["network"] == network:
                    res.append(w_name)
            return res

    @property
    def balances_string(self):
        balances_list = []
        for b in self.wallet_balances:
            balances_list.append(f"{b.asset_code} {b.balance}")
        if balances_list:
            return ", ".join(balances_list)
        else:
            return "failed to get balances.. maybe not activated?"


    
    def do_transfer(self, dest, amount_str, asset_str, memo):
            try:
                self._stellarwallet.transfer(dest, amount_str, asset_str, memo_text=memo)
                showinfo(title="Success!", message="Money sent successfully")
            except Exception as e:
                err = str(e)
                showerror(title="Error!", message=err)

    def show_about_message(self):
        showinfo(title="StellarGUI", message="stellarGUI developed by xmonader.\nHomepage: github.com/xmonader/stellargui")

    def show_add_network_dialog(self):
        networkdisplaynamevar = StringVar()
        networkpassphrasevar = StringVar()
        networkhorizonvar = StringVar()
        should_reload = False

        dlg = Toplevel(self.root)

        def dismiss():
            dlg.grab_release()
            dlg.destroy()

        def add():
            nonlocal should_reload
            displayname = networkdisplaynamevar.get()
            passphrase = networkpassphrasevar.get()
            horizon = networkhorizonvar.get()
            try:
                self.save_network({"name":displayname, "network_passphrase":passphrase, "horizon":horizon})
            except Exception as e:
                showerror("Error", str(e))
            else:
                showinfo(title="Network Add", message=f"Network {displayname} added successfully")
                should_reload = True

        ttk.Label(dlg, text="Display name").grid(column=0, row=0, sticky=(W))
        networkdisplaynameentry = ttk.Entry(dlg, textvariable=networkdisplaynamevar)
        networkdisplaynameentry.grid(column=1, row=0, columnspan=2, sticky=(W, E))
        networkdisplaynameentry.insert(0, networkdisplaynamevar.get())

        ttk.Label(dlg, text="Passphrase").grid(column=0, row=1, sticky=(W))
        passphraseentry = ttk.Entry(dlg, textvariable=networkpassphrasevar)
        passphraseentry.grid(column=1, row=1, columnspan=2, sticky=(W, E))
        passphraseentry.insert(0, networkpassphrasevar.get())

        ttk.Label(dlg, text="Horizon").grid(column=0, row=2, sticky=W)
        horizon = ttk.Entry(dlg, textvariable=networkhorizonvar)
        horizon.grid(column=1, row=2, columnspan=1, sticky=(W, E))


        ttk.Button(dlg, text="Add network", command=add).grid(column=0, row=4, sticky=(W, E))
        ttk.Button(dlg, text="Close", command=dismiss).grid(column=2, row=4, sticky=(W, E))

        for child in dlg.winfo_children():
            child.grid_configure(padx=2, pady=2)

        dlg.columnconfigure(0, weight=1)
        dlg.columnconfigure(1, weight=1)
        dlg.columnconfigure(2, weight=1)

        dlg.rowconfigure(0, weight=1)
        dlg.rowconfigure(1, weight=1)
        dlg.rowconfigure(2, weight=1)

        dlg.protocol("WM_DELETE_WINDOW", dismiss)  # intercept close button
        dlg.transient(self.root)  # dialog window is related to main
        dlg.wait_visibility()  # can't grab until window appears, so we wait
        dlg.grab_set()  # ensure all input goes to our window
        dlg.wait_window()  # block until window is destroyed


    def show_add_wallet_dialog(self):
        walletdisplaynamevar = StringVar()
        newwalletaddrvar = StringVar()
        newwalletsecretvar = StringVar()
        networkvar = StringVar()
        should_reload = False

        dlg = Toplevel(self.root)

        def dismiss():
            dlg.grab_release()
            dlg.destroy()

        def add():
            nonlocal should_reload
            network = networkvar.get()
            displayname = walletdisplaynamevar.get()
            secret = newwalletsecretvar.get()
            try:
                w = Stellar(displayname, secret=secret, network=self.networks[network])
                self.save_wallet(w.to_dict())
                showinfo(title='Wallet added', message="successfully imported the wallet")
            except Exception as e:
                showerror("Error", str(e))
            else:
                should_reload = True

        def generate():
            nonlocal should_reload

            network_name = networkvar.get()
            network = self.networks[network_name]
            displayname = walletdisplaynamevar.get()
            try:
                w = Stellar(displayname, network=network)
                newwalletaddrvar.set(w.address)
                newwalletsecretvar.set(w.secret)
                self.save_wallet(w.to_dict())
                if network_name == "TESTNET":
                    t = threading.Thread(target=w.activate_through_friendbot)
                    t.start()
            except Exception as e:
                print(e)
                showerror("Error", str(e))
            else:

                should_reload = True

        ttk.Label(dlg, text="Display name").grid(column=0, row=0, sticky=(W))
        walletdisplaynameentry = ttk.Entry(dlg, textvariable=walletdisplaynamevar)
        walletdisplaynameentry.grid(column=1, row=0, columnspan=2, sticky=(W, E))
        walletdisplaynameentry.insert(0, walletdisplaynamevar.get())

        ttk.Label(dlg, text="Address").grid(column=0, row=1, sticky=(W))
        newwalletaddrentry = ttk.Entry(dlg, textvariable=newwalletaddrvar)
        newwalletaddrentry.grid(column=1, row=1, columnspan=2, sticky=(W, E))
        newwalletaddrentry.insert(0, newwalletaddrvar.get())

        ttk.Label(dlg, text="Secret").grid(column=0, row=2, sticky=W)
        newwalletsecret = ttk.Entry(dlg, textvariable=newwalletsecretvar)
        newwalletsecret.grid(column=1, row=2, columnspan=1, sticky=(W, E))

        ttk.Label(dlg, text="Network").grid(column=0, row=3, sticky=W)
        network_combo = ttk.Combobox(dlg, textvariable=networkvar, values=self.list_all_networks())
        network_combo.grid(column=1, row=3, columnspan=1, sticky=(W, E))
        network_combo.current(0)
        ttk.Button(dlg, text="Add wallet", command=add).grid(column=0, row=4, sticky=(W, E))
        ttk.Button(dlg, text="Generate", command=generate).grid(column=1, row=4, sticky=(W, E))
        ttk.Button(dlg, text="Close", command=dismiss).grid(column=2, row=4, sticky=(W, E))

        for child in dlg.winfo_children():
            child.grid_configure(padx=2, pady=2)

        dlg.columnconfigure(0, weight=1)
        dlg.columnconfigure(1, weight=1)
        dlg.columnconfigure(2, weight=1)

        dlg.rowconfigure(0, weight=1)
        dlg.rowconfigure(1, weight=1)
        dlg.rowconfigure(2, weight=1)

        dlg.protocol("WM_DELETE_WINDOW", dismiss)  # intercept close button
        dlg.transient(self.root)  # dialog window is related to main
        dlg.wait_visibility()  # can't grab until window appears, so we wait
        dlg.grab_set()  # ensure all input goes to our window
        dlg.wait_window()  # block until window is destroyed
        return should_reload


    def show_payment_details_dialog(self, payment_obj):
        dlg = Toplevel(self.root)


        def dismiss():
            dlg.grab_release()
            dlg.destroy()

        ttk.Label(dlg, text="From").grid(column=0, row=0, sticky=(W, E))
        entryfrom = ttk.Entry(dlg, text=payment_obj.from_address)
        entryfrom.grid(column=1, row=0, sticky=(W, E))
        entryfrom.insert(0, payment_obj.from_address)
        entryfrom.configure(state="readonly")


        ttk.Label(dlg, text="To").grid(column=0, row=1, sticky=(W, E))
        entryto=ttk.Entry(dlg, text=payment_obj.to_address)
        entryto.grid(column=1, row=1, sticky=(W, E))
        entryto.insert(0, payment_obj.to_address)
        entryto.configure(state="readonly")

        ttk.Label(dlg, text="Amount").grid(column=0, row=2, sticky=(W, E))
        ttk.Label(dlg, text=payment_obj.balance).grid(column=1, row=2, sticky=(W, E))


        ttk.Label(dlg, text="Payment Type").grid(column=0, row=3, sticky=(W, E))
        ttk.Label(dlg, text=payment_obj.payment_type).grid(column=1, row=3, sticky=(W, E))


        ttk.Label(dlg, text="TX Hash").grid(column=0, row=4, sticky=(W, E))
        entryhash = ttk.Entry(dlg, text=payment_obj.transaction_hash)
        entryhash.grid(column=1, row=4, sticky=(W, E))
        entryhash.insert(0, payment_obj.transaction_hash)

        ttk.Button(dlg, text="Close", command=dismiss).grid(column=0, columnspan=4, row=4, sticky=(W, E))

        for child in dlg.winfo_children():
            child.grid_configure(padx=2, pady=2)

        dlg.columnconfigure(0, weight=1)
        dlg.columnconfigure(1, weight=1)
        dlg.columnconfigure(2, weight=1)

        dlg.rowconfigure(0, weight=1)
        dlg.rowconfigure(1, weight=1)
        dlg.rowconfigure(2, weight=1)

        dlg.protocol("WM_DELETE_WINDOW", dismiss)  # intercept close button
        dlg.transient(self.root)  # dialog window is related to main
        dlg.wait_visibility()  # can't grab until window appears, so we wait
        dlg.grab_set()  # ensure all input goes to our window
        dlg.wait_window()  # block until window is destroyed




    def show_transactions_dialog(self):

        dlg = Toplevel(self.root)


        def dismiss():
            dlg.grab_release()
            dlg.destroy()

        paymentsvar = StringVar()
        txs_listbox = Listbox(dlg, selectmode=SINGLE, listvariable=paymentsvar)
        yscroll = ttk.Scrollbar(dlg, orient=VERTICAL, command=txs_listbox.yview)
        xscroll = ttk.Scrollbar(dlg, orient=HORIZONTAL, command=txs_listbox.xview)
        txs_listbox.configure(yscrollcommand=yscroll.set)
        txs_listbox.configure(xscrollcommand=xscroll.set)
        txs_listbox.grid(column=0, row=1, columnspan=8, sticky=(N, W, E, S))
        yscroll.grid(column=8, row=1, sticky=(N, S))
        xscroll.grid(column=0, row=2, columnspan=8, sticky=(W, E))
        payments = None

        def show_tx_info(selectiontup):
            idx = selectiontup[0]
            print("idx:", idx)
            print("payments:", payments)
            payment = payments[idx]
            self.show_payment_details_dialog(payment)

        def do_list_payments():
            nonlocal payments
            payments = self._stellarwallet.list_payments()
            payments_strs = []
            for p in payments:
                if p.from_address == p.my_address:
                    payments_strs.append(f"paid {p.balance} to {p.to_address}")
                elif p.to_address == p.my_address:
                    payments_strs.append(f"received {p.balance} from {p.from_address}")

            paymentsvar.set(payments_strs)
        t = threading.Thread(target=do_list_payments)
        t.start()

        ttk.Button(dlg, text="Close", command=dismiss).grid(column=0, columnspan=4, row=4, sticky=(W, E))
        txs_listbox.bind("<Double-1>", lambda e: show_tx_info(txs_listbox.curselection()) )

        for child in dlg.winfo_children():
            child.grid_configure(padx=2, pady=2)

        dlg.columnconfigure(0, weight=1)
        dlg.columnconfigure(1, weight=1)
        dlg.columnconfigure(2, weight=1)

        dlg.rowconfigure(0, weight=1)
        dlg.rowconfigure(1, weight=1)
        dlg.rowconfigure(2, weight=1)

        dlg.protocol("WM_DELETE_WINDOW", dismiss)  # intercept close button
        dlg.transient(self.root)  # dialog window is related to main
        dlg.wait_visibility()  # can't grab until window appears, so we wait
        dlg.grab_set()  # ensure all input goes to our window
        dlg.wait_window()  # block until window is destroyed



    def build_ui(self):

        self.root = None
        self.has_ttkthemes = False
        try:
            import ttkthemes
        except ImportError:
            self.root = Tk()
        else:
            self.has_ttkthemes = True
            self.root = ttkthemes.ThemedTk()
            
        # self.root.iconbitmap(APP_ICON_PATH)
        # self.root.tk.call('wm', 'iconphoto', self.root._w, PhotoImage(file=APP_ICON_PATH))

        def center_win():

            w = 750
            h = 320

            # sw = self.root.winfo_screenwidth()
            # sh = self.root.winfo_screenheight()

            # x = (sw - w)/2
            # y = (sh - h)/2
            # self.root.geometry('%dx%d+%d+%d' % (w, h, x, y))
            self.root.geometry(f"{w}x{h}")
        center_win()
        self.root.title("StellarGUI")
        s=ttk.Style()
        themes = s.theme_names()
        if self.has_ttkthemes:
            themes = ttkthemes.THEMES

        current_theme_var = StringVar()
        if self.has_ttkthemes:
            current_theme_var.set("plastik")
        else:
            current_theme_var.set("clam")


        # current_theme_var.set(s.theme_use())
        wallets_names = self.filter_wallets_by_network("ALL")
        addr = ""
        wallet_name_var = StringVar()
        horizon_var = StringVar()
        walletaddr = StringVar()
        walletaddr.set(addr)
        destvar = StringVar()
        assetvar = StringVar()
        amountvar = StringVar()
        memovar = StringVar()
        secret_holder = ""
        secretvar = StringVar(value=secret_holder)
        showsecretvar = IntVar(value=0)
        walletsnamesvar = StringVar(value=wallets_names)
        active_wallet = StringVar()
        balances_list_string = StringVar()
        combobox_network_filter_var = StringVar(value="ALL")

        wallets_list_frame = ttk.Frame(self.root, padding="3 3 12 12")
        wallets_list_frame.grid(column=0, row=0, columnspan=4, sticky=(N, W, E, S))


        # combobox_theme = ttk.Combobox(
        #     wallets_list_frame, values=themes, textvariable=current_theme_var
        # )
        # combobox_theme.grid(column=0, row=0, columnspan=2, sticky=(W, E))
        
        combobox_network_filter = ttk.Combobox(
            wallets_list_frame, values=("ALL", *self.list_all_networks()), textvariable=combobox_network_filter_var
        )
        combobox_network_filter.grid(column=0, row=1, columnspan=2, sticky=(W, E))


        wallets_listbox = Listbox(wallets_list_frame, selectmode=SINGLE, listvariable=active_wallet)
        scroll = ttk.Scrollbar(wallets_list_frame, orient=VERTICAL, command=wallets_listbox.yview)
        wallets_listbox.configure(yscrollcommand=scroll.set)
        wallets_listbox.grid(column=0, row=2, columnspan=2, sticky=(N, W, E, S))
        scroll.grid(column=2, row=2, sticky=(N, S))
        btn_add_wallet = ttk.Button(wallets_list_frame, text="+")
        btn_add_wallet.grid(column=0, row=3, sticky=(W, E))

        btn_del_wallet = ttk.Button(wallets_list_frame, text="-")
        btn_del_wallet.grid(column=1, row=3, sticky=(W, E))

        wallet_info_frame = ttk.Frame(self.root, padding="3 3 12 12")
        wallet_info_frame.grid(column=4, row=0, sticky=(N, W, E, S))

        ttk.Label(wallet_info_frame, textvariable=wallet_name_var).grid(column=0, row=1, sticky=(W))
        # ttk.Label(wallet_info_frame, text="Horizon").grid(column=1, row=1, sticky=(W))
        ttk.Label(wallet_info_frame, textvariable=horizon_var).grid(column=1, columnspan=2, row=1, sticky=(W, E))

        ttk.Label(wallet_info_frame, text="Address").grid(column=0, row=2, sticky=(W))
        eaddr = ttk.Entry(wallet_info_frame, textvariable=walletaddr)
        eaddr.grid(column=1, row=2, columnspan=2, sticky=(W, E))
        eaddr.config(state="readonly")
        eaddr.insert(0, walletaddr)

        ttk.Label(wallet_info_frame, text="Secret").grid(column=0, row=3, sticky=W)
        es = ttk.Entry(wallet_info_frame, textvariable=secretvar)
        es.grid(column=1, row=3, columnspan=1, sticky=(W, E))
        es.config(state="readonly")

        check_showsecret = ttk.Checkbutton(wallet_info_frame, text="Show secret", variable=showsecretvar)
        check_showsecret.grid(column=2, row=3, sticky=W)

        ttk.Label(wallet_info_frame, text="Balances").grid(column=0, row=4, sticky=W)

        ttk.Label(wallet_info_frame, textvariable=balances_list_string).grid(column=1, row=4, sticky=W)

        ttk.Label(wallet_info_frame, text="Destination").grid(column=0, row=5, sticky=W)
        ttk.Entry(wallet_info_frame, textvariable=destvar).grid(column=1, row=5, columnspan=2, sticky=(W, E))

        ttk.Label(wallet_info_frame, text="Memo").grid(column=0, row=6, sticky=W)
        ttk.Entry(wallet_info_frame, textvariable=memovar).grid(column=1, row=6, columnspan=2, sticky=(W, E))

        ttk.Label(wallet_info_frame, text="Amount").grid(column=0, row=7, sticky=W)
        ttk.Entry(wallet_info_frame, textvariable=amountvar).grid(column=1, row=7, sticky=(W, E))

        cb_assets = ttk.Combobox(wallet_info_frame, textvariable=assetvar, values=[])
        cb_assets.grid(column=2, row=7, sticky=(W, E))

        btn_transfer = ttk.Button(wallet_info_frame, text="Transfer")
        btn_transfer.grid(column=0, columnspan=2, row=8, sticky=(W, E))

        btn_transactions = ttk.Button(wallet_info_frame, text="Transactions")
        btn_transactions.grid(column=2, columnspan=3, row=8, sticky=(W, E))

        for child in wallet_info_frame.winfo_children():
            child.grid_configure(padx=2, pady=2)
        for child in wallets_list_frame.winfo_children():
            child.grid_configure(padx=2, pady=2)

        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(4, weight=3)

        self.root.rowconfigure(0, weight=1)

        for i in range(8):
            wallet_info_frame.columnconfigure(i, weight=1)

        for i in range(8):
            wallet_info_frame.rowconfigure(i, weight=1)

        wallets_list_frame.columnconfigure(0, weight=1)
        wallets_list_frame.rowconfigure(0, weight=1)
        # wallets_list_frame.columnconfigure(0, weight=1)
        wallets_list_frame.rowconfigure(1, weight=1)


        def _reload_vars():
            nonlocal addr, destvar, horizon_var, wallet_name_var, assetvar, secretvar, active_wallet, wallets_names, showsecretvar, balances_list_string, combobox_network_filter_var
            if self._stellarwallet:

                wallet_name_var.set(self._stellarwallet.name)
                addr = str(self._stellarwallet.address)
                secret_holder = "X" * len(self._stellarwallet.secret)
                secretvar.set(value=secret_holder)
                active_wallet.set(self._stellarwallet.name)
                cb_assets.configure(values=self.assets_names)
                eaddr.insert(0, walletaddr)
                secretvar.set(secret_holder)
                walletaddr.set(addr)
                balances_list_string.set(self.balances_string)
                horizon_var.set(self.horizon_url)

            wallets_names = self.filter_wallets_by_network(combobox_network_filter_var.get() or "ALL")

            # showsecretvar.set(False)
            walletsnamesvar.set(wallets_names)

            wallets_listbox.configure(listvariable=walletsnamesvar)
            center_win()


        def reload_vars():
            threading.Thread(target=_reload_vars).start()

        def update_activewallet(selectiontup):
            if selectiontup:
                idx = selectiontup[0]
                wallets_listbox.see(idx)
                self._horizon_server_url = None

                w_dict = self.wallets[wallets_names[idx]]
                network = self.networks[w_dict["network"]]
                w_obj = Stellar(w_dict["name"], network, w_dict["secret"])
                self._stellarwallet = w_obj

                t = threading.Thread(target=reload_vars)
                t.start()

        def send_money():
            dest = destvar.get()
            asset = assetvar.get()
            memo = memovar.get()
            # amount = int(amountvar.get())

            if not (self._stellarwallet and destvar.get() and amountvar.get() and assetvar.get()):
                showinfo(
                    "Here to help",
                    "choose a wallet from the left side and fill in the destination, amount and the asset",
                )
                return
            amount_str = amountvar.get()
            asset_str = self.asset_str_from_code(asset)
            t = threading.Thread(target=self.do_transfer, args=(dest, amount_str, asset_str, memo))
            t.start()

        def togglesecret():
            if showsecretvar.get():
                secretvar.set(self._stellarwallet.secret)
            else:
                secretvar.set(secret_holder)

        def show_transactions_cb():
            self.show_transactions_dialog()

        def add_wallet_cb():
            should_reload_vars = self.show_add_wallet_dialog()
            if should_reload_vars:
                reload_vars()

        def add_network_cb():
            should_reload_vars = self.show_add_network_dialog()
            if should_reload_vars:
                reload_vars()

        def delete_wallet_cb():
            seltup = wallets_listbox.curselection()
            if seltup:
                idx = seltup[0]
                wname = self.filter_wallets_by_network(combobox_network_filter_var.get())[idx]
                answer = askquestion("Deleting wallet", f"Are you sure you want delete wallet {wname}", icon="warning")
                if answer == "yes":
                    self.delete_wallet(wname)

        def theme_changed_cb(ev):
            if not self.has_ttkthemes:
                s.theme_use(current_theme_var.get())
            else:
                self.root.set_theme(current_theme_var.get())

        def get_theme_changer_fun(theme_name):

            def fun():
                print("called with theme name:", theme_name)
                current_theme_var.set(theme_name)
                theme_changed_cb(None)
            return fun


        def combobox_network_filter_changed(ev):
            reload_vars()

        wallets_listbox.bind("<<ListboxSelect>>", lambda e: update_activewallet(wallets_listbox.curselection()))
        wallets_listbox.bind("<Double-1>", lambda e: update_activewallet(wallets_listbox.curselection()))
        combobox_network_filter.bind("<<ComboboxSelected>>", combobox_network_filter_changed)
        # combobox_theme.bind("<<ComboboxSelected>>", theme_changed_cb)

        btn_transfer.configure(command=send_money)
        btn_transactions.configure(command=self.show_transactions_dialog)
        check_showsecret.configure(command=togglesecret)
        btn_add_wallet.configure(command=add_wallet_cb)
        btn_del_wallet.configure(command=delete_wallet_cb)
        theme_changed_cb(None)

        menubar = Menu(self.root)
        self.root.configure(menu=menubar)
        file_menu = Menu(menubar)
        file_menu.add_command(label='Add Wallet', command=add_wallet_cb)
        file_menu.add_command(label='Add Network', command=add_network_cb)
        file_menu.add_command(label='Exit', command=exit)
        
        view_menu = Menu(menubar)
        themes_view_menu = Menu(view_menu)
        for t in themes:
            themes_view_menu.add_command(label=t, command=get_theme_changer_fun(t))

        view_menu.add_cascade(label='Theme', underline=0, menu=themes_view_menu)


        about_menu = Menu(menubar)
        about_menu.add_command(label='About StellarGUI', command=self.show_about_message)
        about_menu.add_command(label='Visit Homepage', command=lambda: webbrowser.open_new_tab("https://github.com/xmonader/stellargui"))

        menubar.add_cascade(label='File', underline=0, menu=file_menu)
        menubar.add_cascade(label='View', underline=0, menu=view_menu)
        menubar.add_cascade(label='About', underline=0, menu=about_menu)

        reload_vars()

    def start(self):
        self.build_ui()
        self.root.mainloop()


def run():
    g = StellarGUI()
    g.prep()
    g.start()


if __name__ == "__main__":
    run()