# config.py

MAINNET = False

if MAINNET:
	# dash mainnet
	wif_prefix  = 204  # cc
	addr_prefix = 76   # 4c
else:
	# dash testnet
	wif_prefix  = 239 # ef
	addr_prefix = 140 # 8c

#