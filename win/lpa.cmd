@echo off
rem Laya packet analyser. "lpa.cmd" = live capture (asks for Administrator via UAC); "lpa.cmd analyse file.pcapng"; "lpa.cmd --help".
rem Uses LPA_PYTHON if set, otherwise the Windows "py" launcher (Python 3.10+; no packages needed).
setlocal
set "PYTHONPATH=%~dp0"
if defined LPA_PYTHON ("%LPA_PYTHON%" -X utf8 -m lpa %*) else (py -3 -X utf8 -m lpa %*)
