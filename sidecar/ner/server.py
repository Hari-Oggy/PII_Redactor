import grpc
from concurrent import futures
import logging
import ner_pb2
import ner_pb2_grpc
from presidio_analyzer import AnalyzerEngine

class NERServiceServicer(ner_pb2_grpc.NERServiceServicer):
    def __init__(self):
        logging.info("Initializing Presidio Analyzer Engine...")
        self.analyzer = AnalyzerEngine()
        logging.info("Presidio Analyzer Engine initialized.")

    def Analyze(self, request, context):
        text = request.text
        if not text:
            return ner_pb2.AnalyzeResponse()

        # Call presidio analyzer
        try:
            results = self.analyzer.analyze(text=text, language='en')
            
            entities = []
            for result in results:
                # Map Presidio Entity to Protobuf Entity
                entities.append(ner_pb2.Entity(
                    entity_type=result.entity_type,
                    start=result.start,
                    end=result.end,
                    score=result.score
                ))

            return ner_pb2.AnalyzeResponse(entities=entities)

        except Exception as e:
            logging.error(f"Error analyzing text: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return ner_pb2.AnalyzeResponse()

def serve():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    ner_pb2_grpc.add_NERServiceServicer_to_server(NERServiceServicer(), server)
    
    # Listen on all interfaces so Docker can expose it
    server.add_insecure_port('[::]:50051')
    logging.info("NER gRPC Server starting on port 50051...")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
