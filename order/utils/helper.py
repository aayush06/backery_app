import uuid

from django.template.loader import get_template
from django.core.files.base import ContentFile
from weasyprint import HTML


class GenerateInvoice:
    pdf_template_name = 'invoice.html'

    def generate_pdf(self, base_url, **ctx):
        html_template = get_template(self.pdf_template_name)
        html = html_template.render(ctx)
        pdf_file = HTML(string=html, base_url=base_url).write_pdf()
        return pdf_file

    def generate_pdf_invoice(self, order, base_url, **ctx):
        """ generate pdf file code from the html file """
        pdf = self.generate_pdf(base_url, **ctx)
        order.invoice_path.save(
            'invoice_report_'+str(uuid.uuid4())[:4]+'.pdf',
            ContentFile(pdf)
        )
        return pdf
