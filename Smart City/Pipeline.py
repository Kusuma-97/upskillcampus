import pandas as pd, numpy as np
import holidays
from xgboost import XGBRegressor
 
IN_HOLIDAYS = holidays.India(years=range(2015, 2018))
 
def add_calendar_features(df):
    df = df.copy()
    dt = df['DateTime']
    df['Hour'] = dt.dt.hour
    df['Day'] = dt.dt.day
    df['Month'] = dt.dt.month
    df['Year'] = dt.dt.year
    df['DayOfWeek'] = dt.dt.dayofweek
    df['IsWeekend'] = (df['DayOfWeek'] >= 5).astype(int)
    df['WeekOfYear'] = dt.dt.isocalendar().week.astype(int)
    df['DayOfYear'] = dt.dt.dayofyear
    df['Quarter'] = dt.dt.quarter
    df['IsHoliday'] = dt.dt.date.astype('O').apply(lambda d: 1 if d in IN_HOLIDAYS else 0)
    df['IsMonthStart'] = dt.dt.is_month_start.astype(int)
    df['IsMonthEnd'] = dt.dt.is_month_end.astype(int)
    # cyclical encodings
    df['Hour_sin'] = np.sin(2*np.pi*df['Hour']/24)
    df['Hour_cos'] = np.cos(2*np.pi*df['Hour']/24)
    df['DOW_sin'] = np.sin(2*np.pi*df['DayOfWeek']/7)
    df['DOW_cos'] = np.cos(2*np.pi*df['DayOfWeek']/7)
    df['Month_sin'] = np.sin(2*np.pi*df['Month']/12)
    df['Month_cos'] = np.cos(2*np.pi*df['Month']/12)
    return df
 
CAL_COLS = ['Hour','Day','Month','Year','DayOfWeek','IsWeekend','WeekOfYear',
            'DayOfYear','Quarter','IsHoliday','IsMonthStart','IsMonthEnd',
            'Hour_sin','Hour_cos','DOW_sin','DOW_cos','Month_sin','Month_cos','Trend']
 
LAGS = [1, 24, 48, 168]
ROLLS = [24, 168]
 
def build_series_frame(junction_train, junction_test, trend_start):
    """Combine train+test datetime index for a junction, with Vehicles known for train, NaN for test."""
    full_dt = pd.concat([junction_train[['DateTime']], junction_test[['DateTime']]]).sort_values('DateTime').reset_index(drop=True)
    full = add_calendar_features(full_dt)
    full['Trend'] = (full['DateTime'] - trend_start).dt.total_seconds() / 3600.0
    veh = junction_train.set_index('DateTime')['Vehicles']
    full = full.set_index('DateTime')
    full['Vehicles'] = veh
    full['IsTest'] = full['Vehicles'].isna().astype(int)
    return full
 
def compute_lag_features(full, upto_idx, series_values):
    """series_values: numpy array with known+predicted values up to (not including) upto_idx."""
    row_feats = {}
    for lag in LAGS:
        idx = upto_idx - lag
        row_feats[f'lag_{lag}'] = series_values[idx] if idx >= 0 else np.nan
    for win in ROLLS:
        start = max(0, upto_idx - win)
        window = series_values[start:upto_idx]
        window = window[~np.isnan(window)]
        row_feats[f'roll_mean_{win}'] = window.mean() if len(window) > 0 else np.nan
        row_feats[f'roll_std_{win}'] = window.std() if len(window) > 1 else 0.0
    return row_feats
 
FEATURE_LAG_COLS = [f'lag_{l}' for l in LAGS] + [f'roll_mean_{w}' for w in ROLLS] + [f'roll_std_{w}' for w in ROLLS]
ALL_FEATURES = CAL_COLS + FEATURE_LAG_COLS
 
def prepare_training_table(full):
    """Build a training table using only known (train) rows, with lag features computed from the true series (non-recursive, since all history is known)."""
    values = full['Vehicles'].values.astype(float)
    n = len(values)
    rows = []
    for i in range(n):
        if np.isnan(values[i]):
            continue
        feats = compute_lag_features(full, i, values)
        rows.append(feats)
    lag_df = pd.DataFrame(rows, index=full.index[~full['Vehicles'].isna()])
    table = full.loc[~full['Vehicles'].isna(), CAL_COLS + ['Vehicles']].join(lag_df)
    return table
 
def recursive_forecast(full, model):
    """Forecast the NaN (test) rows in order, updating the series with predictions as we go."""
    values = full['Vehicles'].values.astype(float).copy()
    n = len(values)
    is_test = full['IsTest'].values
    cal = full[CAL_COLS].values
    preds = {}
    for i in range(n):
        if is_test[i] == 1:
            feats = compute_lag_features(full, i, values)
            x = list(cal[i]) + [feats[c] for c in FEATURE_LAG_COLS]
            x = np.array(x).reshape(1, -1)
            yhat = model.predict(x)[0]
            yhat = max(0, yhat)
            values[i] = yhat
            preds[full.index[i]] = yhat
    return pd.Series(preds)
 
def train_final_model(full_train_df, model_type='xgb'):
    """Train on ALL available training data for a junction (full_train_df already has calendar+lag features)."""
    X = full_train_df[ALL_FEATURES]
    y = full_train_df['Vehicles']
    if model_type == 'xgb':
        m = XGBRegressor(n_estimators=500, max_depth=6, learning_rate=0.05,
                          subsample=0.9, colsample_bytree=0.9, random_state=42, n_jobs=4)
    else:
        from lightgbm import LGBMRegressor
        m = LGBMRegressor(n_estimators=500, max_depth=6, learning_rate=0.05,
                           subsample=0.9, colsample_bytree=0.9, random_state=42, verbosity=-1)
    m.fit(X, y)
    return m