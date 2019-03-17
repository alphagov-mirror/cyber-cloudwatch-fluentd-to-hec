.DEFAULT_GOAL := zip
.PHONY = clean

target_dir:
	mkdir -p .target

copy_src: target_dir
	cp fluentdhec/* .target

add_deps: target_dir
	pip3 install -r requirements.txt --system -t .target

clean:
	rm -rf .target *.egg-info .tox venv *.zip .pytest_cache
	find . -type d -regex ".*__pycache__$$" -exec rm -rf {} \;

zip: add_deps copy_src
	cd .target; zip -9 ../cyber-cloudwatch-fluentd-to-hec -r .
