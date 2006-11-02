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

<xsl:template match="cms:page[@name]">
  <xsl:document href="{@name}.html"
                doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN"
                doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"
  >
    <html>
      <head>
        <title><xsl:apply-templates select="cms:title"/></title>
	<link rel="stylesheet" href="style.css"/>
      </head>
      <body>
        <table class="main">
           <tr> 
              <td class="menu">
                 <xsl:apply-templates mode="menu" 
                                      select="/cms:pageset/cms:page">
                   <xsl:with-param name="current" select="."/>
                 </xsl:apply-templates>
              </td>
              <td class="content">
                 <h1><xsl:apply-templates select="cms:title"/></h1>
                 <xsl:apply-templates select="cms:content/*"/>
              </td>
           </tr>
         </table>
         <div class="footer">
           <xsl:apply-templates select="/cms:pageset/cms:footer/*"/>
         </div>
      </body>
    </html>
  </xsl:document>
</xsl:template>

<xsl:template match="cms:page[@href]"/>

<xsl:template match="cms:menuitem">
  <xsl:apply-templates/>
</xsl:template>

<xsl:template mode="menu" match="cms:page[@name]">
  <xsl:param name="current"/>
  <div class="menu">
    <xsl:choose>
      <xsl:when test=". != $current">
        <a href="{@name}.html"><xsl:apply-templates select="cms:menuitem"/></a>
      </xsl:when>
      <xsl:otherwise>
        <xsl:apply-templates select="cms:menuitem"/>
      </xsl:otherwise>
    </xsl:choose>
  </div>
</xsl:template>

<xsl:template mode="menu" match="cms:page[@href]">
  <div class="menu">
    <a href="{@href}"><xsl:apply-templates select="cms:menuitem"/></a>
  </div>
</xsl:template>

<xsl:template match="@*|xhtml:*">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()"/>
  </xsl:copy>
</xsl:template>

</xsl:stylesheet>
