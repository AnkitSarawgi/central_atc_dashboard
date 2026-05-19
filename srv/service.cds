using { atc_Run } from '../db/schema';

@path: '/odata/v4/atc'
@requires: 'any'
service ATCService {

  @readonly entity Runs as projection on atc_Run;

  @readonly entity Trend {
    key date : String;
        p1   : Integer;
        p2   : Integer;
        p3   : Integer;
  }

  @readonly entity Radar {
    key subject : String;
        value   : Integer;
  }

  @readonly entity SLA {
    key name  : String;
        value : Integer;
  }

  @readonly entity OverviewKPI {
    key ID     : UUID;
        p1     : Integer;
        p2     : Integer;
        p3     : Integer;
        health : Integer;
  }

  @readonly entity CategoryStats {
    key name  : String;
        value : Integer;
  }

  @readonly entity RunSeriesStats {
    key name  : String;
        value : Integer;
  }

  @readonly entity QualityTrend {
    key date  : String;
        score : Integer;
  }

  @readonly entity Heatmap {
    key ID    : UUID;
        value : Integer;
  }
}
