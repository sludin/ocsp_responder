FROM        perl:latest
MAINTAINER  Stephen Ludin sludin@ludin.org

RUN curl -L http://cpanmin.us | perl - App::cpanminus
RUN cpanm Carton

RUN git clone http://git.ludin.org/ocsp_responder.git
#RUN cd ocsp_repsonder & carton install --deployment

EXPOSE 8888

WORKDIR ocsp_responder
CMD perl ocsp_responder.pl
