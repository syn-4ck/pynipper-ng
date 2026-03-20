from enum import Enum

# TODO: Support to other devices


class DeviceType(Enum):
    IOS_SWITCH = "Cisco IOS-based Switch"
    IOS_ROUTER = "Cisco IOS-based Router"  # default
    IOS_CATALYST = "Cisco IOS-based Catalyst"
    '''
    # PIX=4           #Cisco PIX-based Firewall
    # ASA=5           #Cisco ASA-based Firewall
    # FWSM=6          #Cisco FWSM-based Router
    # CATOS=7         #Cisco CatOS-based Catalyst
    # NMP=8           #Cisco NMP-based Catalyst
    # CSS=9           #Cisco Content Services Switch
    # SCREENOS=10     #Juniper NetScreen Firewall
    # PASSPORT=11     #Nortel Passport Device
    # SONICOS=12      #SonicWall SonicOS Firewall
    # FW1=13          #CheckPoint Firewall-1 Firewall
    '''
