#! /usr/bin/env python

import asyncio
from dataclasses import dataclass, field
import socket
import ssl
from typing import *

import aioconsole
from OpenSSL.crypto import X509, PKey
import pprint
import structlog
import urllib

from .ia_jimmy import public_to_private
from .ia_jimmy import JimmyCrackerException

@dataclass
class Deps:
    running:bool = True
    logger :Any  = field(default_factory=structlog.get_logger)
deps:Deps = Deps()

maxsize     :int           = 1
input_queue :asyncio.Queue = asyncio.Queue(maxsize=maxsize)
output_queue:asyncio.Queue = asyncio.Queue(maxsize=maxsize)
crack_queue :asyncio.Queue = asyncio.Queue(maxsize=maxsize)

async def input_loop()->None:
    while deps.running:
        url:str = await aioconsole.ainput('Url: ')
        await input_queue.put(url)
        await asyncio.sleep(0.)

async def output_loop()->None:
    while deps.running:
        pkey  :PKey = await output_queue.get()
        output:str  = pprint.pformat(pkey, indent=2)
        await aioconsole.aprint('Private Key: ',output)
        await asyncio.sleep(0.)

async def fetch_loop()->None:
    while deps.running:
        url   :str           = await input_queue.get()
        pubkey:Optional[str] = await fetch_pubkey(url)
        if not pubkey:
            await asyncio.sleep(0.)
            continue
        await crack_queue.put(pubkey)

async def fetch_pubkey(url:str)->Optional[str]:
    parsed       = urllib.parse.urlparse(url) # TODO typehints
    scheme  :str = parsed.scheme
    hostname:str = parsed.hostname or ''
    port    :int = parsed.scheme   or get_default_port_for_scheme(scheme)
    scheme, port = upgrade_scheme_to_ssl(scheme, port)
    context      = ssl.create_default_context()
    try:
        with await asyncio.to_thread(socket.create_connection, (hostname, port)) as sock:
            with await asyncio.to_thread(context.wrap_socket, sock, server_hostname=hostname) as ssock:
                cert  :bytes = await asyncio.to_thread(ssock.getpeercert, True)
                pubkey:str   = ssl.DER_cert_to_PEM_cert(cert)
                return pubkey
    except Exception as error:                # TODO fine-grained types
        await deps.logger.aerror(error)
        return None

upgrades:Dict[str,str] = {
    'ftp' : 'ftps',
    'http': 'https',
}
defports:Dict[str,int] = {
    'ftp'  :  21,
    'http' :  80,
    'https': 443,
    'ftps' : 990,
}

def get_default_port_for_scheme(scheme:str)->int:
    # TODO how to get default ports in python ?
    # TODO /etc/services ?
    return defports[scheme]

def upgrade_scheme_to_ssl(scheme:str, port:int)->Tuple[str,int]:
    if is_ssl_scheme(scheme): return scheme, port
    scheme = upgrades[scheme]
    return scheme, get_default_port_for_scheme(scheme)

def is_ssl_scheme(scheme:str)->bool:
    if scheme in upgrades.values():
        return True
    if scheme in upgrades.keys():
        return False
    raise Exception(f'unrecognized scheme: {scheme}')

async def crack_loop()->None:
    while deps.running:
        pubkey:str = await crack_queue.get()
        try:
            pkey:PKay = await asyncio.to_thread(public_to_private, pubkey)
        except JimmyCrackerException as error:
            await deps.logger.aerror(error)
            continue
        await output_queue.put(pkey)

async def main()->None:
    await asyncio.gather(
            input_loop(),
            output_loop(),
            fetch_loop(),
            crack_loop(),
    )

if __name__ == '__main__':
    asyncio.run(main())
