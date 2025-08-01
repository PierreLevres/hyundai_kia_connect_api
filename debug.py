
from hyundai_kia_connect_api import Vehicle
from hyundai_kia_connect_api import VehicleManager

from params import *
from dataclasses import dataclass, field
from typing import Optional, List
import datetime
from enum import Enum

import logging
import pprint
import os
global _LOGGER
global pp
from simple_term_menu import TerminalMenu
from hyundai_kia_connect_api.ApiImpl import (
    ApiImpl,
    ClimateRequestOptions,
)
def main():
    # create logger
    _LOGGER = logging.getLogger()
    _LOGGER.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', '%d-%m-%Y %H:%M:%S')


    stdout_handler = logging.StreamHandler()
    stdout_handler.setLevel(logging.INFO)
    stdout_handler.setFormatter(formatter)

    file_handler = logging.FileHandler('apilog.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    _LOGGER.addHandler(file_handler)
    _LOGGER.addHandler(stdout_handler)

    pp = pprint.PrettyPrinter(indent=1,compact=True)

    s_pin = ('0000' + (str(p_pin) if isinstance(p_pin, int) else p_pin))[-4:] #pin filling with 0's at front
    geolocation_enable = True
    geolocation_use_email = False
    print('****** CREATE A VEHICLE MANAGER *******')
    vehicle_manager = VehicleManager(
        region=1,
        brand=1,
        username=p_email,
        password=p_password,
        pin=s_pin,
        geocode_api_enable=True,
        geocode_api_use_email=False,
        language="nl"
    )
    print('****** INITIALIZE THE VEHICLE MANAGER *******')
    vehicle_manager.initialize()
    print('****** VEHICLE TO MANAGE: *******')
    vehicleID = list(vehicle_manager.vehicles.keys())[0]
    try:
        print('****** FORCE UPDATE *******')
        vehicle_manager.check_and_force_update_vehicles(30)
        print('****** FORCE UPDATE JUST RAN *******')
    except Exception as err:
        try:
            print('****** FAILED, UPDATE FROM CACHE *******')
            vehicle_manager.update_all_vehicles_with_cached_state
            print('****** UPDATE FROM CACHE JUST RAN *******')
            _LOGGER.exception(
                f"Force update failed, falling back to cached: {err}"
            )
        except Exception as err_nested:
            raise print(f"Error communicating with API: {err_nested}")

    print('****** VEHICLE GOT SOME DATA *******')
    vehicle=vehicle_manager.vehicles[vehicleID]
    pp.pprint(vehicle)
    print('******** DATA LOADED ********')
    options = ["0 exit", "1 start A/C" ,"2 stop A/C", "3 vehicles", "4 odometer", "5 lock",'6 unlock',"7 locate",
               "8 status from cache","9 refresh cache", "10 open charge port", "11 close charge port"

               "[EU] monthly report", "[EU] trip informations", "[EU] drive informations", "[EV] get charge targets","[EV] set charge targets","[EV] start charging","[EV] stop charging"
               ]
    terminal_menu = TerminalMenu(options)
    while True:
        menu_entry_index = terminal_menu.show()
        print(f"You have selected {options[menu_entry_index]}!")
        if menu_entry_index == 0: break
        elif menu_entry_index == 1:
            settings = ClimateRequestOptions()
            settings.set_temp = 21.5

            vehicle_manager.start_climate(vehicleID, settings)
        elif menu_entry_index == 2: vehicle_manager.stop_climate(vehicleID)
        elif menu_entry_index == 3: print(vehicle.name, vehicle.model, vehicle.VIN)
        elif menu_entry_index == 4: print(vehicle._odometer)
        elif menu_entry_index == 4: vehicle_manager.stop_climate(vehicleID)
        elif menu_entry_index == 5: vehicle_manager.lock(vehicleID)
        elif menu_entry_index == 6: vehicle_manager.unlock(vehicleID)
        elif menu_entry_index == 7: print(vehicle._geocode_address)
        elif menu_entry_index == 8:
            vehicle_manager.update_vehicle_with_cached_state(vehicleID)
            print(vehicle.data)
        elif menu_entry_index == 9:
            vehicle_manager.force_refresh_vehicle_state(vehicleID)
        elif menu_entry_index == 10:
            vehicle_manager.open_charge_port(vehicleID)
        elif menu_entry_index == 11:
            vehicle_manager.close_charge_port(vehicleID)
        input("press key");
    return

if __name__ == '__main__':
    main()
