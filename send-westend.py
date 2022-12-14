from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException
from scalecodec.base import ScaleBytes, RuntimeConfiguration, ScaleDecoder
from scalecodec.types import Extrinsic
import sys


metadata_substrate_node_template  = "0x00" # dummy
substrate = SubstrateInterface(url="wss://westend-rpc.polkadot.io:443", ss58_format=42)

metadata_decoder = RuntimeConfiguration().create_scale_object(
    'MetadataVersioned', ScaleBytes(metadata_substrate_node_template)
)


extrinsicBytes = sys.argv[1]
if not extrinsicBytes.startswith("0x"):
    extrinsicBytes = "0x" + extrinsicBytes
extrinsic = Extrinsic(metadata=metadata_decoder, data=ScaleBytes(extrinsicBytes))
print(extrinsic.extrinsic_hash.hex())

try:
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=False)
    print(f"Extrinsic '{receipt.extrinsic_hash}' sent and included in block '{receipt.block_hash}'")

except SubstrateRequestException as e:
    print("Failed to send: {}".format(e))


