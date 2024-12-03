# grafana dashboards for Hammerspace
Grafana dashboards for use with the prometheus exporters built into Hammerspace

The 5.1 directory is used for Hammerspace releases 5.1 and newer
The 5.0 directory is used for Hammerspace release 5.0


# To Configure Prometheus

XXX gen_prom_config.py

# To Configure Grafana
Grafana version 11 is recommended

### Login

Go to http://<grafana_host>:3000/ and login, default is typically admin/admin and set your own password

### Setup data source

Under the settings icon, add a prometheus data source. It shows a default URL
of http://localhost:9090, assuming promethus is running on the same host, that
is the correct address but you have to type this in. Leave the name as the
default, "Prometheus".

### Add (or update) Hammerspace dashboards

If you have existing hammerspace dashboards, please delete them.  if you have
made changes you may want to do a dashboards_page->settings->save_as and save
with a new name then delete.

click New->import.  Use the upload from my computer.  Sadly they must each be
added indvidually.  On the second page you MUST select the prometheus data
source configured above.

### Add 3rd party dashboards

In grafana, click New->Import

To add node exporter, use id method with id 1860
