IF "%~1"=="" (
    echo Error: No COM port specified.
    exit /b 1
)
rmdir /s /q twister-out
SET PATH=C:\ncs\toolchains\b620d30767\opt\bin;C:\ncs\toolchains\b620d30767\opt\bin\Scripts;%PATH%
python C:\ncs\v2.9.0\zephyr\scripts\twister -T rs_protocol_test -p nrf52840dk/nrf52840 --device-testing --device-serial %1
