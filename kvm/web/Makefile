
all:
	xsltproc -o html/ generate.xslt content.xml
	cp style.css html/

publish:
	scp -r html/. shell.sourceforge.net:/home/groups/k/kv/kvm/htdocs/
