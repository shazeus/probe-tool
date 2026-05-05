from __future__ import annotations

import typer

from probe.config import load_config, set_setting
from probe.modules import cred, encode, fuzz, hash, jwt_scan, network, osint, report, ssl_scan, web
from probe.utils.display import console as rich_console, print_panel

app = typer.Typer(
    name="probe",
    help="probe - multi-module penetration testing CLI",
    no_args_is_help=True,
)
config_app = typer.Typer(help="Manage probe configuration")

app.add_typer(web.app, name="web")
app.add_typer(network.app, name="network")
app.add_typer(cred.app, name="cred")
app.add_typer(hash.app, name="hash")
app.add_typer(encode.app, name="encode")
app.add_typer(osint.app, name="osint")
app.add_typer(ssl_scan.app, name="ssl")
app.add_typer(jwt_scan.app, name="jwt")
app.add_typer(fuzz.app, name="fuzz")
app.add_typer(report.app, name="report")
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show():
    """Show current configuration."""
    config = load_config()
    lines = [f"{key}: {value}" for key, value in config.items()]
    print_panel("Config", "\n".join(lines))


@config_app.command("set")
def config_set(key: str, value: str):
    """Set a configuration value."""
    valid_keys = {"timeout", "threads", "output_dir"}
    if key not in valid_keys:
        rich_console.print(f"[red]Unknown key '{key}'. Valid: {', '.join(sorted(valid_keys))}[/red]")
        raise typer.Exit(1)

    parsed: object = value
    if key == "threads":
        try:
            parsed = int(value)
        except ValueError:
            rich_console.print("[red]threads must be an integer[/red]")
            raise typer.Exit(1)
    elif key == "timeout":
        try:
            parsed = float(value)
        except ValueError:
            rich_console.print("[red]timeout must be a number[/red]")
            raise typer.Exit(1)

    set_setting(key, parsed)
    rich_console.print(f"[green]Set {key} = {parsed}[/green]")


def app_entry():
    app()


if __name__ == "__main__":
    app_entry()
