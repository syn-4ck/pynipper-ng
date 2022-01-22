import click
import os

from .common.banner import display_banner
from .analyze.analyze_device import analyze_device

@click.command()
@click.option('-d', '--device', 
              help='Device type to analyze: Cisco IOS devices [IOS_SWITCH, IOS_ROUTER, IOS_CATALYST]', 
              required=True, 
              type=click.Choice(["IOS_SWITCH", "IOS_ROUTER", "IOS_CATALYST"], case_sensitive=False)
            )
@click.option('-i', '--input-filename', 
              help='Device configuration file to analyze', 
              required=True, 
              type=click.Path(exists=True)
            )
@click.option('-f', '--output-filename', 
              help='Report filename', 
              required=False, 
              type=click.Path(exists=False),
              default="./report.html"
            )
@click.option('-o', '--output-type', 
              help='Report type: HTML (by default), JSON', 
              required=False, 
              type=click.Choice(["HTML", "JSON"]),
              default="HTML"
            )
@click.option('-c', '--configuration', 
              help='Pynipper-ng configuration file', 
              required=False, 
              type=click.Path(exists=True),
              default=os.path.dirname(os.path.abspath(__file__)) + "/common/default.conf"
            )
@click.option('-x', '--online', 
              help='Enable get APIs vulnerabilities data (Cisco API)', 
              is_flag=True
            )
def main(device, input_filename, output_filename, output_type, configuration, online) -> int:

    display_banner()

    analyze_device(device, input_filename, output_filename, output_type, configuration, online)

    return 0


if __name__ == "__main__":
    main()
