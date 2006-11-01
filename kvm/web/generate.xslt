<xsl:stylesheet version="1.0" 
     xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
     xmlns:cms="http://www.qumranet.com/silly-cms"
     xmlns:xhtml="http://www.w3.org/1999/xhtml" 
     xmlns="http://www.w3.org/1999/xhtml" 
>
<xsl:output encoding="utf-8"/>

<xsl:template match="/">
  <xsl:apply-templates select="cms:pageset/cms:page"/>
</xsl:template>

<xsl:template match="cms:page">
  <xsl:document href="{@name}.html">
    <html>
      <head>
        <title><xsl:apply-templates select="cms:title"/></title>
      </head>
      <body>
        <h1><xsl:apply-templates select="cms:title"/></h1>
        <xsl:apply-templates select="cms:content/*"/>
      </body>
    </html>
  </xsl:document>
</xsl:template>

<xsl:template match="cms:menuitem">
  <xsl:apply-templates/>
</xsl:template>

<xsl:template match="@*|xhtml:*">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()"/>
  </xsl:copy>
</xsl:template>

</xsl:stylesheet>