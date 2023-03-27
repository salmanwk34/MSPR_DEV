import dash

from dash import html

from dash import dcc

from dash.dependencies import Input, Output

import subprocess

import re

import pandas as pd

import nmap

import socket

import ipaddress

import requests

import socket

import dns.query

import dns.update

import ifaddr

import os


# Fonction pour récupérer l'adresse IP locale

def adresse_ip_recuperation():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.connect(("8.8.8.8", 80))

    local_ip = s.getsockname()[0]

    s.close()

    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)

    return str(network)


# Fonction pour scanner le réseau et retourner un DataFrame Pandas avec les résultats

def scan_network():
    target = adresse_ip_recuperation()

    nm = nmap.PortScanner()

    nm.scan(target, arguments="-sS -O")

    rows = []

    for host in nm.all_hosts():

        hostname = nm[host].hostname()

        for proto in nm[host].all_protocols():

            lport = nm[host][proto].keys()

            lport = sorted(lport)

            for port in lport:
                state = nm[host][proto][port]['state']

                rows.append((host, hostname, proto, port, state))

    df = pd.DataFrame(rows, columns=["Host", "Hostname", "Protocol", "Port", "State"])

    return df


# Fonction pour récupérer l'adresse IP publique

def adresse_ip_publique():
    response = requests.get('https://api.ipify.org')

    ip = response.text

    return ip

app = dash.Dash(__name__)

app.layout = html.Div([

    html.H1('Tableau de bord de l\'analyse de réseau'),

    html.Button('Scan', id='button-scan'),

    html.Div(id='output-table'),

    html.Div([

        dcc.Input(id='input-ip', type='text', value='192.168.1.1'),

        html.Button(id='button-ping', children='Ping')

    ]),

    html.Div(id='output-result'),

    html.Div([

        html.Button('Adresse IP publique', id='button-ip-publique'),

        html.Div(id='output-ip-publique')

    ])

])


@app.callback(

    Output('output-table', 'children'),

    Input('button-scan', 'n_clicks')

)
def update_output(n_clicks):
    if n_clicks is not None:
        df = scan_network()

        table = html.Table([

            html.Thead(

                html.Tr([

                    html.Th("Host"),

                    html.Th("Hostname"),

                    html.Th("Protocol"),

                    html.Th("Port"),

                    html.Th("State")

                ])

            ),

            html.Tbody([

                html.Tr([

                    html.Td(df.iloc[i]["Host"]),

                    html.Td(df.iloc[i]["Hostname"]),

                    html.Td(df.iloc[i]["Protocol"]),

                    html.Td(port),

                    html.Td(df.iloc[i]["State"])

                ]) for i, port in enumerate(df['Port'])

            ])

        ])

        return table


@app.callback(

    Output('output-result', 'children'),

    Input('button-ping', 'n_clicks'),

    Input('input-ip', 'value')

)
def ping(n_clicks, ip):
    if n_clicks is not None:

        result = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE)

        output = result.stdout.decode('utf-8')

        latency = None

        match = re.search(r'time=(\d+\.\d+) ms', output)

        if match:
            latency = float(match.group(1))

        if latency is not None:

            return f'Ping réussi. Latence: {latency} ms'

        else:

            return 'Ping échoué.'


# Fonction pour récupérer l'adresse IP publique

def adresse_ip_publique_recuperation():
    response = requests.get('https://api.ipify.org')

    return response.text


app.layout = html.Div([

    html.H1('Tableau de bord de l\'analyse de réseau'),

    html.Button('Scan', id='button-scan'),

    html.Div(id='output-table'),

    html.Div([

        dcc.Input(id='input-ip', type='text', value='192.168.1.1'),

        html.Button(id='button-ping', children='Ping')

    ]),

    html.Div(id='output-result'),

    html.Div([

        html.Button('Adresse IP publique', id='button-ip'),

        html.Div(id='output-ip')

    ])

])


@app.callback(

    Output('output-ip', 'children'),

    Input('button-ip', 'n_clicks')

)
def update_output(n_clicks):
    if n_clicks is not None:
        ip = adresse_ip_publique_recuperation()

        return f'Adresse IP publique: {ip}'


hostnamefordn = socket.gethostname()


def get_net_address() -> str:
    interfaces = ifaddr.get_adapters()

    for interface in interfaces:

        if interface.nice_name == "tun0":

            for ip in interface.ips:

                if ip.is_IPv4:
                    return ip.ip

            break


def add_dns_record(domain, ip_dns, host, new_ip, enregistrement, ttl):
    update = dns.update.Update(domain)

    update.add(host, ttl, enregistrement, new_ip)

    response = dns.query.tcp(update, ip_dns)

    if response.rcode() == 0:

        return "Enregistrement DNS ajouté avec succès"

    else:

        return "Erreur lors de l'ajout de l'enregistrement DNS"


def update_dns_record():
    return add_dns_record(

        domain='cma4.box',

        ip_dns='192.168.2.1',

        host=hostnamefordn,

        new_ip=get_net_address(),

        enregistrement='A',

        ttl=300,

    )


app.layout = html.Div([

    html.H1('Tableau de bord de l\'analyse de réseau'),

    html.Button('Scan', id='button-scan'),

    html.Div(id='output-table'),

    html.Div([

        dcc.Input(id='input-ip', type='text', value='192.168.1.1'),

        html.Button(id='button-ping', children='Ping')

    ]),

    html.Div(id='output-result'),

    html.Div([

        html.Button('Adresse IP publique', id='button-ip'),

        html.Div(id='output-ip')

    ]),

    html.H3("Ajout d'un enregistrement DNS"),

    html.Button('Mettre à jour l\'enregistrement DNS', id='button'),

    html.Br(),

    html.Div(id='output'),

])


@app.callback(Output('output', 'children'), Input('button', 'n_clicks'))
def update_output(n_clicks):
    if n_clicks is not None:
        return update_dns_record()


app.layout = html.Div([

    html.H1('SemaBox'),

    html.H3("Scan réseau"),
    html.Button('Scanner', id='button-scan'),

    html.Div(id='output-table'),

    html.Div([
        html.H3("Ping Basique"),

        dcc.Input(id='input-ip', type='text', value='192.168.1.1'),

        html.Button(id='button-ping', children='Ping')

    ]),

    html.Div(id='output-result'),

    html.Div([
        html.H3("IP Publique"),

        html.Button('Obtenir', id='button-ip'),

        html.Div(id='output-ip')

    ]),
    html.Div([
        html.H3("Ajout d'un enregistrement DNS"),

        html.Button('Mettre à jour', id='button'),

        html.Br(),

        html.Div(id='output'),

    ]),

    html.H3("Redémarrage de la semabox"),

    html.Button('Redémarrer', id='btn-restart'),

    html.Div(id='output-rt'),

])


@app.callback(Output('output-rt', 'children'),

              Input('btn-restart', 'n_clicks'))
def restart_machine(n_clicks):
    if n_clicks is not None and n_clicks > 0:
        os.system("shutdown -r -t 1")

        return "Machine redémarrée avec succès"

    return ""


if __name__ == '__main__':
    app.run_server(debug=True, host='0.0.0.0')
