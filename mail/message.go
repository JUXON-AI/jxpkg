package mail

import (
	"bytes"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
	"time"
)

func buildMessage(config Config, message Message) ([]byte, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := message.validate(); err != nil {
		return nil, err
	}

	from, _ := parseAddress(config.From)
	recipients := make([]string, 0, len(message.To))
	for _, value := range message.To {
		address, _ := parseAddress(value)
		recipients = append(recipients, address.String())
	}

	var output bytes.Buffer
	fmt.Fprintf(&output, "From: %s\r\n", from.String())
	fmt.Fprintf(&output, "To: %s\r\n", strings.Join(recipients, ", "))
	fmt.Fprintf(&output, "Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", message.Subject))
	fmt.Fprintf(&output, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	output.WriteString("MIME-Version: 1.0\r\n")

	if message.Text != "" && message.HTML != "" {
		var parts bytes.Buffer
		writer := multipart.NewWriter(&parts)
		contentType := mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": writer.Boundary()})
		fmt.Fprintf(&output, "Content-Type: %s\r\n\r\n", contentType)
		if err := writePart(writer, "text/plain; charset=UTF-8", message.Text); err != nil {
			return nil, fmt.Errorf("%w: build text body", ErrInvalidMessage)
		}
		if err := writePart(writer, "text/html; charset=UTF-8", message.HTML); err != nil {
			return nil, fmt.Errorf("%w: build HTML body", ErrInvalidMessage)
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("%w: close multipart body", ErrInvalidMessage)
		}
		_, _ = output.Write(parts.Bytes())
		return output.Bytes(), nil
	}

	contentType := "text/plain; charset=UTF-8"
	body := message.Text
	if body == "" {
		contentType = "text/html; charset=UTF-8"
		body = message.HTML
	}
	fmt.Fprintf(&output, "Content-Type: %s\r\n", contentType)
	output.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	if err := writeQuotedPrintable(&output, body); err != nil {
		return nil, fmt.Errorf("%w: build body", ErrInvalidMessage)
	}
	return output.Bytes(), nil
}

func writePart(writer *multipart.Writer, contentType, body string) error {
	header := make(textproto.MIMEHeader)
	header.Set("Content-Type", contentType)
	header.Set("Content-Transfer-Encoding", "quoted-printable")
	part, err := writer.CreatePart(header)
	if err != nil {
		return err
	}
	return writeQuotedPrintable(part, body)
}

func writeQuotedPrintable(output interface{ Write([]byte) (int, error) }, body string) error {
	writer := quotedprintable.NewWriter(output)
	if _, err := writer.Write([]byte(body)); err != nil {
		return err
	}
	return writer.Close()
}
